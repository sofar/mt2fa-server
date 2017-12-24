package main

import (
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"github.com/badoux/checkmail"
	_ "github.com/mattn/go-sqlite3" // MIT licensed.
	"github.com/spf13/viper"
	"gopkg.in/gomail.v2"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"time"
)

// DB related stuff
var db *sql.DB

type Token struct {
	token     string
	cookie    string
	created   int64
	expiry    int64
	request   []byte
	confirmed bool
}

type Server struct {
	server_id string
	created   int64
	email     string
	data      string
	ip        string
}

type Identity struct {
	email   string
	created int64
	data    string
}

type Player struct {
	email     string
	name      string
	server_id string
	created   int64
	data      string
}

// JSON data blobs
type Player_data struct {
	Auth_required string `json:"auth_required"`
}

// JSON interface to WWW, and gameserver
type Serverdata struct {
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	Address     string `json:"address"`
	Url         string `json:"url"`
	Announce    string `json:"announce"`
	AnnounceUrl string `json:"announce_url"`
}

type tfa_request struct {
	// required
	Request_type string `json:"request_type"`
	Remote_ip    string `json:"remote_ip"`
	// optional, need to verify they're present at a later stage
	Email      string     `json:"email",omitempty`
	Player     string     `json:"player",omitempty`
	Server_id  string     `json:"server_id",omitempty`
	Token      string     `json:"token",omitmempty`
	Cookie     string     `json:"cookie",omitempty`
	Serverdata Serverdata `json:"server_data"`
}

type tfa_response struct {
	Result string `json:"result"`
	Info   string `json:"info"`
	// optional
	Data map[string]string `json:"data"`
}

// misc functions
func make_token() string {
	b := make([]byte, 24)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal("Error creating token: ", err)
	}

	s := base32.StdEncoding.EncodeToString(b)

	return s[:len(s)-1]
}

func validate_email(email string) bool {
	err := checkmail.ValidateFormat(email)
	if err != nil {
		log.Printf("email: %v: %v\n", email, err)
		return false
	}
	//FIXME enable this when not running behind a NAT
	//err = checkmail.ValidateHost(email)
	//if err != nil {
	//	log.Printf("email: %v: %v\n", email, err)
	//}
	//if smtpErr, ok := err.(checkmail.SmtpError); ok && err != nil {
	//	log.Printf("email: %v: code: %s, msg: %s", email, smtpErr.Code(), smtpErr)
	//	return false
	//}
	return true
}

func do_email(email string, message string) bool {
	m := gomail.NewMessage()
	m.SetHeader("From", viper.GetString("email_sender"))
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Minetest 2-factor confirmation request")
	m.SetBody("text/plain", message)

	d := gomail.Dialer{Host: viper.GetString("smtp_server"), Port: viper.GetInt("smtp_port")}
	if viper.GetBool("smtp_verify_certificate") == false {
		d.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if err := d.DialAndSend(m); err != nil {
		log.Println(err)
		return false
	}

	return true
}

type FastCGIServer struct{}

func (s FastCGIServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// track IP of client, we'll need it later for some transactions
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		http.Error(w, err.Error(), 500)
		log.Print("Request: unable to identify peer\n")
		return
	}
	remoteip := net.ParseIP(ip).String()

	// parse POST data
	body, err := ioutil.ReadAll(req.Body)
	defer req.Body.Close()
	if err != nil {
		http.Error(w, err.Error(), 500)
		log.Printf("Request: %v: unable to read body\n", remoteip)
		return
	}

	var rq tfa_request
	err = json.Unmarshal(body, &rq)
	if err != nil {
		http.Error(w, err.Error(), 500)
		log.Printf("Request: %v: malformed JSON data\n", remoteip)
		return
	}
	rq.Remote_ip = remoteip

	// create response
	var rp tfa_response

	// prefetch server name for requestst that want it
	servername := "(no name)"
	if rq.Request_type == "REG" || rq.Request_type == "AUTH" {
		// get relevant info, ignore errors
		var data []byte
		err = db.QueryRow("SELECT data FROM servers WHERE server_id=?", rq.Server_id).Scan(&data)
		if err == nil {
			var sd Serverdata
			err = json.Unmarshal(data, &sd)
			if err == nil && sd.Name != "" {
				servername = sd.Name
			}
		}
	}

	// validate request origin is valid
	var orip string
	err = db.QueryRow("SELECT ip FROM servers WHERE server_id=?", rq.Server_id).Scan(&orip)
	if err != nil || orip != remoteip {
		switch rq.Request_type {
		case "CONFIRM":
		case "SERVER":
		case "SERVERSTAT":
		case "SERVERIP":
		case "SERVERIPSTAT":
		default:
			rp = tfa_response{"SERVERIPFAIL", "The server IP address changed. The server owner will need to confirm\nthis change before normal events can be handled again.", nil}
			goto send_response
		}
	}

	// process request
	switch rq.Request_type {
	case "REG":
		if rq.Email == "" || rq.Player == "" || rq.Server_id == "" {
			rp = tfa_response{"REGFAIL", "Registration failed, insufficient data.", nil}
			break
		}
		if !validate_email(rq.Email) {
			rp = tfa_response{"REGFAIL", "Registration failed, email invalid.", nil}
			break
		}

		// check identities table for rq.Email
		var created int64
		err := db.QueryRow("SELECT created FROM identities WHERE email=?", rq.Email).Scan(&created)
		if err == nil {
			// already created? could just happen
			var created int64
			err = db.QueryRow("SELECT created FROM players WHERE email=? AND player=?", rq.Email, rq.Player).Scan(&created)
			if err == nil {
				rp = tfa_response{"REGOK", "This email is already registered.", nil}
				break
			}
			// store the server/player combo
			_, err = db.Exec("INSERT INTO players(email, name, server_id, created, data) VALUES (?, ?, ?, ?, ?)",
				rq.Email, rq.Player, rq.Server_id, time.Now().Unix(), "{}")
			if err != nil {
				rp = tfa_response{"REGFAIL", "Internal server error.", nil}
				break
			}
			// looks like this was already registered as an identity!
			rp = tfa_response{"REGOK", "This email is already registered.", nil}
			break
		}

		// no existing identity
		token := make_token()
		cookie := make_token()

		// send the confirmation email
		if !do_email(rq.Email,
			"\nHello,\n\n"+
				"You've received this request because you or someone registered this email\n"+
				"address on a minetest server at \""+servername+"\".\n\n"+
				"If this wasn't you, you can safely ignore this email. If it was you, please\n"+
				"click the following link to confirm your registration:\n\n"+
				"  " + viper.GetString("base_url") + "confirm?t="+token+"\n\n") {
			rp = tfa_response{"REGFAIL", "Registration failed, unable to send email.", nil}
			break
		}

		// store the token
		j, err := json.Marshal(rq)
		if err != nil {
			log.Println(err)
			rp = tfa_response{"REGFAIL", "Registration failed, internal server error.", nil}
			break
		}
		t := Token{token, cookie, time.Now().Unix(), time.Now().Unix() + 300, j, false}
		_, err = db.Exec("INSERT INTO tokens(token, cookie, created, expiry, request) VALUES (?, ?, ?, ?, ?)",
			t.token, t.cookie, t.created, t.expiry, t.request)
		if err != nil {
			log.Println(err)
			rp = tfa_response{"REGFAIL", "Registration failed, internal server error.", nil}
			break
		}

		rp = tfa_response{"REGPEND", "Mail sent. Check your mailbox.", nil}
		rp.Data = make(map[string]string)
		rp.Data["Cookie"] = cookie
	case "REGSTAT":
		var created int64
		err := db.QueryRow("SELECT created FROM identities WHERE email=?", rq.Email).Scan(&created)
		if err == nil {
			rp = tfa_response{"REGOK", "Registration succeeded.", nil}
			break
		}
		// check if a token exists.
		var confirmed bool
		err = db.QueryRow("SELECT confirmed FROM tokens WHERE cookie=?", rq.Cookie).Scan(&confirmed)
		if err == nil {
			if confirmed {
				// badness
				rp = tfa_response{"REGFAIL", "Internal server error.", nil}
				break
			}
			rp = tfa_response{"REGPEND", "Mail sent. Check your mailbox.", nil}
			break
		}
		rp = tfa_response{"REGFAIL", "Registration failed.", nil}
	case "AUTH":
		// check server token + username combo exists
		var email string
		err := db.QueryRow("SELECT email FROM players WHERE name=? AND server_id=?", rq.Player, rq.Server_id).Scan(&email)
		if err != nil {
			rp = tfa_response{"AUTHFAIL", "Authentication failed.", nil}
			break
		}

		// send an AUTH email
		token := make_token()
		cookie := make_token()

		// send the confirmation email
		if !do_email(email,
			"\nHello,\n\n"+
				"You've received this request because you or someone wants to authenticate\n"+
				"using this email address on a minetest server at \""+servername+"\".\n\n"+
				"If this wasn't you, you can safely ignore this email. If it was you, please\n"+
				"click the following link to confirm your authentication:\n\n"+
				"  " + viper.GetString("base_url") + "confirm?t="+token+"\n\n") {
			rp = tfa_response{"AUTHFAIL", "Authentication failed, unable to send email.", nil}
			break
		}

		// store the token
		j, err := json.Marshal(rq)
		if err != nil {
			log.Println(err)
			rp = tfa_response{"AUTHFAIL", "Authentication failed, internal server error.", nil}
			break
		}
		t := Token{token, cookie, time.Now().Unix(), time.Now().Unix() + 300, j, false}
		_, err = db.Exec("INSERT INTO tokens(token, cookie, created, expiry, request) VALUES (?, ?, ?, ?, ?)",
			t.token, t.cookie, t.created, t.expiry, t.request)
		if err != nil {
			log.Println(err)
			rp = tfa_response{"AUTHFAIL", "Authentication failed, internal server error.", nil}
			break
		}

		rp = tfa_response{"AUTHPEND", "Mail sent. Check your mailbox.", nil}
		rp.Data = make(map[string]string)
		rp.Data["Cookie"] = cookie
	case "AUTHSTAT":
		// check tokens
		var confirmed bool
		var expiry int64
		err := db.QueryRow("SELECT confirmed, expiry FROM tokens WHERE cookie=?", rq.Cookie).Scan(&confirmed, &expiry)
		if err != nil {
			// there is no token
			rp = tfa_response{"AUTHFAIL", "Server registration failed.", nil}
			break
		}
		if time.Now().Unix() > expiry {
			rp = tfa_response{"AUTHFAIL", "Authentication failed.", nil}
			break
		}
		if !confirmed {
			rp = tfa_response{"AUTHPEND", "Mail sent. Check your mailbox.", nil}
			break
		}
		rp = tfa_response{"AUTHOK", "Authentication succeeded.", nil}
	case "ACCT":
		// this is sent by a server to see if the account is required to
		// authenticate, and / or to inspect stat data (not implemented yet)
		var data []byte
		var email string
		err := db.QueryRow("SELECT data, email FROM players WHERE name=? AND server_id=?", rq.Player, rq.Server_id).Scan(&data, &email)
		if err != nil {
			rp = tfa_response{"ACCTFAIL", "Request failed.", nil}
			break
		}
		var pd Player_data
		err = json.Unmarshal(data, &pd)
		if pd.Auth_required != "1" {
			err := db.QueryRow("SELECT data FROM identities WHERE email=?", email).Scan(&data)
			if err != nil {
				rp = tfa_response{"ACCTFAIL", "Request failed.", nil}
				break
			}
			err = json.Unmarshal(data, &pd)
			if pd.Auth_required != "1" {
				rp = tfa_response{"ACCTOK", "Account info retrieved.", nil}
				break
			}
		}
		rp = tfa_response{"ACCTOK", "Account info retrieved. Player must authenticate", nil}
		rp.Data = make(map[string]string)
		rp.Data["Auth_required"] = "1"
		// get playerdata struct json
	case "UPDATES":
		// check if server sent server_data changes
		if rq.Serverdata.Owner != "" {
			// refresh server data
			//FIXME make sure all the required fields are present again
			s, err := json.Marshal(rq.Serverdata)
			if err != nil {
				log.Println("Error storing Serverdata")
			} else {
				_, err = db.Exec("UPDATE servers set data=? WHERE server_id=?",
					s, rq.Server_id)
				if err != nil {
					log.Println("Error updating Serverdata")
				} else {
					log.Println(remoteip + ": Updated server info for \"" + servername + "\"")
				}
			}
		}
		//FIXME implement some updates - rp = tfa_response{"UPDATE", "Changes requested.", nil}
		rp = tfa_response{"NOUPDATES", "No changes for server.", nil}
	case "SERVER":
		// server registration request.
		if rq.Email == "" {
			rp = tfa_response{"SERVERFAIL", "Registration failed, insufficient data.", nil}
			break
		}
		if rq.Server_id != "" {
			rp = tfa_response{"SERVERFAIL", "Registration failed, you provided a server id. This server is already registered.", nil}
			break
		}
		if !validate_email(rq.Email) {
			rp = tfa_response{"SERVERFAIL", "Registration failed, email invalid.", nil}
			break
		}

		// validate serverdata is sufficient
		if rq.Serverdata.Owner == "" {
			rp = tfa_response{"SERVERFAIL", "Registration failed, insufficient data.", nil}
			break
		}

		token := make_token()
		cookie := make_token()

		// send the confirmation email
		if !do_email(rq.Email,
			"\nHello,\n\n"+
				"You've received this request because you or someone wants to register\n"+
				"a server using this email address at \""+remoteip+"\".\n\n"+
				"If this wasn't you, you can safely ignore this email. If it was you, please\n"+
				"click the following link to confirm your server registration:\n\n"+
				"  " + viper.GetString("base_url") + "confirm?t="+token+"\n\n") {
			rp = tfa_response{"SERVERFAIL", "Server registration failed, unable to send email.", nil}
			break
		}

		// store the token as "server_id" in the request
		rq.Server_id = token

		// store the token including original request data
		j, err := json.Marshal(rq)
		if err != nil {
			log.Println(err)
			rp = tfa_response{"SERVERFAIL", "Server registration failed, internal server error.", nil}
			break
		}
		t := Token{token, cookie, time.Now().Unix(), time.Now().Unix() + 300, j, false}
		_, err = db.Exec("INSERT INTO tokens(token, cookie, created, expiry, request) VALUES (?, ?, ?, ?, ?)",
			token, cookie, t.created, t.expiry, t.request)
		if err != nil {
			log.Println(err)
			rp = tfa_response{"SERVERFAIL", "Server registration failed, internal server error.", nil}
			break
		}

		rp = tfa_response{"SERVERPEND", "Mail sent. Check your mailbox.", nil}
		// send the token to the server, so that the server can use it to validate the registration
		// after confirmation
		rp.Data = make(map[string]string)
		rp.Data["Cookie"] = cookie
	case "SERVERIP":
		// server IP address request.
		if rq.Email == "" || rq.Server_id == "" {
			rp = tfa_response{"SERVERIPFAIL", "Server IP change failed, insufficient data.", nil}
			break
		}

		// validate email is actually the one on file for this server
		var serverid, email string
		err := db.QueryRow("SELECT server_id, email FROM servers WHERE server_id=? and email=?", rq.Server_id, rq.Email).Scan(&serverid, &email)
		if err != nil {
			rp = tfa_response{"SERVERIPFAIL", "Server IP change failed, invalid data.", nil}
			break
		}

		token := make_token()
		cookie := make_token()

		// send the confirmation email
		if !do_email(rq.Email,
			"\nHello,\n\n"+
				"You've received this request because you or someone wants to change the IP\n"+
				"address of a server using this email address at \""+remoteip+"\".\n\n"+
				"If this wasn't you, you can safely ignore this email. If it was you, please\n"+
				"click the following link to confirm your server IP change:\n\n"+
				"  " + viper.GetString("base_url") + "confirm?t="+token+"\n\n") {
			rp = tfa_response{"SERVERIPFAIL", "Server IP change failed, unable to send email.", nil}
			break
		}

		// store the token including original request data
		j, err := json.Marshal(rq)
		if err != nil {
			log.Println(err)
			rp = tfa_response{"SERVERIPFAIL", "Server IP change failed, internal server error.", nil}
			break
		}
		t := Token{token, cookie, time.Now().Unix(), time.Now().Unix() + 300, j, false}
		_, err = db.Exec("INSERT INTO tokens(token, cookie, created, expiry, request) VALUES (?, ?, ?, ?, ?)",
			token, cookie, t.created, t.expiry, t.request)
		if err != nil {
			log.Println(err)
			rp = tfa_response{"SERVERIPFAIL", "Server IP change failed, internal server error.", nil}
			break
		}

		rp = tfa_response{"SERVERIPPEND", "Mail sent. Check your mailbox.", nil}
		// send the token to the server, so that the server can use it to validate the registration
		// after confirmation
		rp.Data = make(map[string]string)
		rp.Data["Cookie"] = cookie
	case "SERVERSTAT":
		// verify that server_id is registered
		var token string
		var expiry int64
		var confirmed bool
		err := db.QueryRow("SELECT token, expiry, confirmed FROM tokens WHERE cookie=?", rq.Cookie).Scan(
			&token, &expiry, &confirmed)
		if err == nil {
			var created int
			err := db.QueryRow("SELECT created FROM servers WHERE server_id=?", token).Scan(&created)
			if err == nil {
				rp = tfa_response{"SERVEROK", "Server registration succeeded.", nil}
				rp.Data = make(map[string]string)
				rp.Data["Server_id"] = token
				break
			}

			if time.Now().Unix() > expiry {
				rp = tfa_response{"SERVERFAIL", "Server registration failed.", nil}
				break
			}
			if !confirmed {
				rp = tfa_response{"SERVERPEND", "Server registration pending. Check your email.", nil}
				break
			}
		}

		rp = tfa_response{"SERVERFAIL", "Server registration failed. Try again", nil}
		break
	case "SERVERIPSTAT":
		// verify that server_id is registered
		var expiry int64
		var confirmed bool
		err := db.QueryRow("SELECT expiry, confirmed FROM tokens WHERE cookie=?", rq.Cookie).Scan(
			&expiry, &confirmed)
		if err == nil {
			var ip string
			err := db.QueryRow("SELECT ip FROM servers WHERE server_id=?", rq.Server_id).Scan(&ip)
			if err == nil {
				if rq.Remote_ip == ip {
					rp = tfa_response{"SERVERIPOK", "Server IP change succeeded.", nil}
					break
				}
			}

			if time.Now().Unix() > expiry {
				rp = tfa_response{"SERVERIPFAIL", "Server IP change failed.", nil}
				break
			}
			if !confirmed {
				rp = tfa_response{"SERVERIPPEND", "Server IP change pending. Check your email.", nil}
				break
			}
		}

		rp = tfa_response{"SERVERIPFAIL", "Server IP change failed. Try again", nil}
		break

	//
	// www initiated requests
	//
	case "CONFIRM":
		if rq.Token == "" {
			rp = tfa_response{"CONFIRMFAIL", "Invalid confirmation.", nil}
			break
		}

		// fetch entry from tokens table
		var ot Token
		err := db.QueryRow("SELECT created, expiry, request, confirmed FROM tokens WHERE token=?",
			rq.Token).Scan(&ot.created, &ot.expiry, &ot.request, &ot.confirmed)
		if err != nil {
			rp = tfa_response{"CONFIRMFAIL", "Internal server error.", nil}
			break
		}

		// check if we didn't already do this
		if ot.confirmed {
			rp = tfa_response{"CONFIRMOK", "Request already completed before.", nil}
			break
		}

		// check if token not too old
		if time.Now().Unix() > ot.expiry {
			rp = tfa_response{"CONFIRMFAIL", "Request token expired. Create a new request.", nil}
			break
		}

		// fetch original request
		var or tfa_request
		err = json.Unmarshal(ot.request, &or)
		if err != nil {
			rp = tfa_response{"CONFIRMFAIL", "Internal server error.", nil}
			break
		}

		// complete the transaction!
		if or.Request_type == "REG" {
			_, err = db.Exec("INSERT INTO identities (email, created, data) VALUES (?, ?, ?)",
				or.Email, time.Now().Unix(), "{}")
			if err != nil {
				rp = tfa_response{"CONFIRMFAIL", "Internal server error.", nil}
				break
			}

			// Mark as done
			_, err = db.Exec("UPDATE tokens SET confirmed=? WHERE token=?",
				true, rq.Token)
			if err != nil {
				rp = tfa_response{"CONFIRMFAIL", "Internal server error.", nil}
				break
			}

			// store the server/player combo
			_, err = db.Exec("INSERT INTO players(email, name, server_id, created, data) VALUES (?, ?, ?, ?, ?)",
				or.Email, or.Player, or.Server_id, time.Now().Unix(), "{}")
			if err != nil {
				rp = tfa_response{"CONFIRMFAIL", "Internal server error.", nil}
				break
			}

			// Nothing left to do
			rp = tfa_response{"CONFIRMOK", "Request completed. Your identity is now registered.", nil}
			break

		} else if or.Request_type == "AUTH" {
			// Mark as done
			_, err = db.Exec("UPDATE tokens SET confirmed=? WHERE token=?",
				true, rq.Token)
			if err != nil {
				rp = tfa_response{"CONFIRMFAIL", "Internal server error.", nil}
				break
			}

			// Nothing left to do
			rp = tfa_response{"CONFIRMOK", "Request completed. You are now authenticated.", nil}
			break

		} else if or.Request_type == "SERVER" {
			s, err := json.Marshal(or.Serverdata)
			if err != nil {
				s = []byte("{}")
				log.Println("Error storing Serverdata")
			}
			_, err = db.Exec("INSERT INTO servers (server_id, email, created, data, ip) VALUES (?, ?, ?, ?, ?)",
				or.Server_id, or.Email, time.Now().Unix(), s, or.Remote_ip)
			if err != nil {
				rp = tfa_response{"CONFIRMFAIL", "Internal server error.", nil}
				break
			}

			// Mark as done
			_, err = db.Exec("UPDATE tokens SET confirmed=? WHERE token=?",
				true, rq.Token)

			if err != nil {
				rp = tfa_response{"CONFIRMFAIL", "Internal server error.", nil}
				break
			}

			// Nothing left to do
			rp = tfa_response{"CONFIRMOK", "Request completed. Your server is now registered.", nil}
			break

		} else if or.Request_type == "SERVERIP" {
			_, err = db.Exec("UPDATE servers SET ip=? WHERE server_id=?",
				or.Remote_ip, or.Server_id)
			if err != nil {
				rp = tfa_response{"CONFIRMFAIL", "Internal server error.", nil}
				break
			}

			// Mark as done
			_, err = db.Exec("UPDATE tokens SET confirmed=? WHERE token=?",
				true, rq.Token)

			if err != nil {
				rp = tfa_response{"CONFIRMFAIL", "Internal server error.", nil}
				break
			}

			// Nothing left to do
			rp = tfa_response{"CONFIRMOK", "Request completed. Your server IP address now changed.", nil}
			break
		} else {
			rp = tfa_response{"CONFIRMFAIL", "Internal server error.", nil}
			break
		}

	//passwdchange
	//emailchange
	default:
		rp = tfa_response{"UNK", "Unknown request type. Don't do that again.", nil}
	}

send_response:
	// and send to the client
	output, err := json.Marshal(rp)
	if err != nil {
		http.Error(w, err.Error(), 500)
		log.Print("Response: formatting response failed\n")
		return
	}

	log.Printf("%v: %v->%v (%v) \"%v\"\n",
		remoteip, rq.Request_type, rp.Result,
		rq.Player, rp.Info)

	w.Header().Set("Content-Type", "application/json")
	w.Write(output)

	//FIXME prune tokens
}

func main() {
	log.SetFlags(0)

	// config stuffs
	viper.SetConfigName("mt2fa")
	viper.SetConfigType("yaml")

	viper.AddConfigPath("/usr/share/defaults/etc")
	viper.AddConfigPath("/etc")
	viper.AddConfigPath("$HOME/.config")

	viper.SetDefault("socket", "/run/mt2fa/sock")

	viper.SetDefault("email_sender", "nobody@localhost.localdomain")
	viper.SetDefault("smtp_server", "localhost")
	viper.SetDefault("smtp_port", 587)
	viper.SetDefault("smtp_verify_certificate", true)
	viper.SetDefault("sqlite_db", "mt2fa.sqlite")
	viper.SetDefault("base_url", "https://localhost/")

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal("Error in confog file: ", err)
	}

	// listen on fcgi socket
	s := viper.GetString("socket")
	os.Remove(s)

	listener, err := net.Listen("unix", s)
	if err != nil {
		log.Fatal("mt2fa: net.Listen: ", err)
	}

	os.Chmod(s, 0666)

	defer listener.Close()

	// open our db
	db, err = sql.Open("sqlite3", viper.GetString("sqlite_db"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// initialize our db as needed
	createStmt := `
	CREATE TABLE IF NOT EXISTS tokens (
		token TEXT NOT NULL PRIMARY KEY,
		cookie TEXT NOT NULL,
		created INTEGER NOT NULL,
		expiry INTEGER NOT NULL,
		request TEXT NOT NULL,
		confirmed BOOLEAN DEFAULT FALSE
	);

	CREATE TABLE IF NOT EXISTS servers (
		server_id TEXT NOT NULL PRIMARY KEY,
		created INTEGER NOT NULL,
		email TEXT NOT NULL,
		data TEXT NOT NULL,
		ip TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS identities (
		email TEXT NOT NULL PRIMARY KEY,
		created INTEGER NOT NULL,
		data TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS players (
		email TEXT NOT NULL,
		name TEXT NOT NULL,
		server_id TEXT NOT NULL,
		created INTEGER NOT NULL,
		data TEXT NOT NULL
	);
	`
	_, err = db.Exec(createStmt)
	if err != nil {
		log.Fatal("%q: %s\n", err, createStmt)
	}

	// serve requests.
	h := new(FastCGIServer)

	log.Print("mt2fa: started")

	err = fcgi.Serve(listener, h)
}
