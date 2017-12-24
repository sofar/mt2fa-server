
## mt2fa-server - Minetest 2factor auth

Provides a simple 2-factor auth module for verifying and maintaining
verification of player identities. Players are required to register
an email address with the 2fa service, and they will receive a login
token through the 2fa service, which is needed for all logins.

A remote 2fa service handles the sending and receiving of emails and
creating the 2fa tokens. This server can be used by many different
servers at the same time.

## License

 (C) 2018 Auke Kok <sofar@foo-projects.org>

 Permission to use, copy, modify, and/or distribute this software
 for any purpose with or without fee is hereby granted, provided
 that the above copyright notice and this permission notice appear
 in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR
BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES
OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

## Operation modes

### 2FA registration voluntary / required

In this simplified mode, an account may, or must be linked to an
email address, but login does not require a 2FA token. This allows
players to recover their lost passwords without requiring the player
to provide a valid 2FA token on each login.

### 2FA authentication voluntary / required

In this mode, the player may, or must enroll in full 2FA authentication
on a voluntary basis. The player must provide a valid 2FA token on
each login after enrollment.

If authentication is required, but registration isn't, then players
who registered are required to authenticate with 2fa, but others can
continue to use normal login.

Each server operator can set minimum requirements. E.g. a server could
require registration, but may leave authentication voluntary.

## client mod

A client mod handles login of new players and requires them to provide
a valid email address. The 2fa service then is queried and if the email
verification succeeds, the client will receive an email with a valid
2fa login token. Once the login token is entered into the game UI, or
confirmed back to the 2FA service, the player is granted permissions
to interact with the game.

## 2fa server

The 2fa server handles incoming game server requests for either new
registrations, or for login events. These result in emails being
sent to the email address. In the registration email, the user is
simply requested to `reply` to the email. In the login event, the
user is provided a one-time password. The user has to enter this
one time password into their game client in order to access game
functionality. Or, the user clicks a link in the email, or, replies
to the email to confirm.

The 2FA server then provides a limited time token to the authentication
mod on the game server.

## account registration

Accounts are registered with the 2fa server, which holds the database
with all the valid accounts. These accounts can be confirmed in
several ways. The main key for each account is a valid e-mail address.

The player receives account emails on their registered email address.
In the registration confirmation, a token is embedded that can be used
to activate the account and therefore make it playable.

The user can confirm the account by responding back to the 2fa server.
This can be done in several ways.

1. https - the user clicks a link with a token in the email.

Not implemented:

2. smtp - the user replies to the email with the token.
3. in game - the user enters the token into the game.

All these methods result in a confirmation event being sent to the 2fa
server, and then activation of the account in the account database.

## account login

If required by the game server, authentication is performed by sending the
player an email with a token that the player needs to reply, click, or
enter in the game client. Once the game server receives the token through
either direct input, or by confirmation from the 2FA server, the client is
granted interact privileges on the game server.

## account recovery

If the player forgets their game server password, the client can attempt
recovery of the game server account by initiating an account recovery.
The game server passes the account recovery request to the 2FA server,
which requests confirmation by the player through e-mail. Once the player
confirms the token through email, click or direct input, the client
may enter a new password for the game server directly into the game
server.

## account exclusivity

(not implemented)

If the player opts in, or, if the server requires it, the account
becomes single-use. This will force the player offline on a server
if the player logs in on another server correctly.

## account monitoring

(not implemented)

Players can monitor and audit their own account information,
authentication requests, failures, recovery attempts and other data
that resides on the 2FA server.

## protocols

The server communicates in several ways through other protocols:

SMTP:
- only outgoing. The server sends emails over SMTP.
- if a user replies, a smtp to https bridge will assure the server
  sees the verification

HTTPS:
- incoming:
    - To receive new account requests
    - to receive 2fa login requests
    - over the web: receive account verification link clicks
- bidir:
    - answer 2fa login status requests

## banning/abuse

(not implemented)

The 2fa server can store account status information, and the game server
can retrieve this information.

The following data items are stored for each account:

ro: data can be retrieved for the account
rw: data can be provided/changed for the account
public: all servers may access this data
private: the data is private to the server

- creation date (public, ro)
- banned here (private, rw)
- bancount here (private, ro)
- playername (private, rw)
- banned (public, ro)
- bancount (public, ro)

The 2fa server does not *act* on this information, it merely provides
it to the servers and acts as a storage of this information. Any player
objection on how this data is *used* by the server owner should be
directed to the server owner.

## changing email addresses

(not implemented)

requires access to both old and new accounts, and verification from both
those accounts, by SMTP mails to both addresses.

## scenario's

* registration

  gameserver -> "REG" packet -> m2tfa
  mt2fa -> "REGPEND" -> gameserver
  mt2fa -> "REGFAIL" -> gameserver
  mt2fa -> SMTP cookie -> mailbox
  mailbox -> click link -> mt2fa (reg ok/reg fail)

  gameserver -> "REGSTAT" -> mt2fa
  mt2fa -> REGOK
  mt2fa -> REGPEND
  mt2fa -> REGFAIL

* authentication

  gameserver -> "AUTH" -> mt2fa
  mt2fa -> "AUTHPEND" -> gameserver
  mt2fa -> "AUTHFAIL" -> gameserver
  mt2fa -> SMTP cookie -> mailbox
  mailbox -> click link -> mt2fa (auth ok/auth fail)

  gameserver -> "AUTHSTAT" -> mt2fa
  mt2fa -> AUTHOK
  mt2fa -> AUTHFAIL
  mt2fa -> AUTHPEND

* fetching account info at login (optional auth)

  gameserver -> "ACCT" -> mt2fa
  mt2fa -> ACCTOK -> gameserver
  mt2fa -> ACCTFAIL -> gameserver

* passreset request

  javascript form -> post -> mt2fa
  mt2fa -> SMTP -> mailbox !confirmation
  mailbox -> click link -> mt2fa
  mt2fa -> SMTP -> mailbox !new password

  gameserver -> "UPDATES" -> mt2fa
  mt2fa -> "UPDATE" -> gameserver
  mt2fa -> "NOUPDATES" -> gameserver

* email change

  javascript form -> post -> mt2fa
  mt2fa -> SMTP -> mailbox !confirmation_old_mailbox
  mailbox -> click link -> mt2fa
  mt2fa -> SMTP -> mailbox !confirmation_new_mailbox
  mailbox -> click link -> mt2fa

  gameserver -> "UPDATES" -> mt2fa
  mt2fa -> "UPDATE" -> gameserver
  mt2fa -> "NOUPDATES" -> gameserver

* server enrollment

  gameserver -> SERVER -> mt2fa
  mt2fa -> SERVERFAIL -> gameserver
  mt2fa -> SERVERPEND -> gameserver
  mt2fa -> SMTP -> mailbox !confirmation
  mailbox -> click link -> mt2fa

  gameserver -> SERVERSTAT -> mt2fa
  mt2fa -> SERVERFAIL -> gameserver
  mt2fa -> SERVERPEND -> gameserver
  mt2fa -> SERVEROK -> gameserver

  -> SERVERIP ->
  SERVERIPFAIL
  SERVERIPPEND
  SERVERIPOK

## Database Schema

CREATE TABLE tokens (
	token TEXT NOT NULL PRIMARY KEY,     -- secret
	cookie TEXT NOT NULL,                -- non-secret
	created INTEGER NOT NULL,            -- DATE first created
	expiry INTEGER NOT NULL,             -- timestamp when no longer valid
	request TEXT NOT NULL,               -- the JSON request context
	confirmed BOOLEAN DEFAULT FALSE,     -- whether a token has been confirmed by a user
)

CREATE TABLE servers (
	server_id TEXT NOT NULL PRIMARY KEY, -- unique identifier, arbitrary string
	created INTEGER NOT NULL,            -- DATE first created
	email TEXT NOT NULL,                 -- associated admin, for confirmation requests
	data TEXT NOT NULL,                  -- JSON encoded data, expandable data format
	ip TEXT NOT NULL,                    -- used to prevent token stealing/spoofing
)

CREATE TABLE identities (
	email TEXT NOT NULL PRIMARY KEY,     -- unique identifier, must be valid email
	created INTEGER NOT NULL,            -- DATE first created
	data TEXT NOT NULL,                  -- JSON encoded data, expandable data format
)

CREATE TABLE players (
	email TEXT NOT NULL,                 -- identity
	name TEXT NOT NULL,                  -- local player name
	server_id TEXT NOT NULL,             -- unique server identity
	created INTEGER NOT NULL,            -- DATE created for this server
	data TEXT NOT NULL,                  -- JSON encoded data, expandable data format
)

