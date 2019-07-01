#!/usr/bin/env python3

import secrets
import sys
from datetime import datetime, timezone

try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from urllib.parse import urlparse, parse_qs
    from http import cookies
except ImportError:
    sys.exit('ERROR: It seems like you are not running Python 3. '
             'This script only works with Python 3!')
import sqlite3
from reset_database import reset_database

DATABASE_FILE = 'website.sqlite3'

form_doc = '''
<!doctype html>
<html><body>
<h1>SEC Intranet</h1>
<form method="post">
    User: <input name="user"> <br>
    Password: <input name="pass" type="password">
<br>
<input type="hidden" name="nonce" value="{nonce}">
<input type="submit" name="action" value="login">
</form>
</body></html>
'''

authenticated_doc = '''
<!doctype html>
<html><body>
<h1>SEC Intranet</h1>
You are logged in as {username}!
<form method="post">
    <input type="submit" name="action" value="logout">
    <input type="hidden" name="nonce" value="{nonce}">
</form>
<br>
If you are an administrator, you can use the <a href="/admin">admin interface</a>.
</body></html>
'''

success = '''
<!doctype html>
<html><body>
<h1>SEC Intranet</h1>
Welcome, {user}!
</html></body>
'''

fail = '''
<!doctype html>
<html><body style="color:red;">
<h1>SEC Intranet</h1>
{message}
</html></body>
'''

sessions = {}
nonce_dict = dict()


class MyHandler(BaseHTTPRequestHandler):

    saved_headers = []

    def get_or_create_session(self):
        cookie_dict = cookies.SimpleCookie(self.headers['Cookie'])

        if 'sid' in cookie_dict:
            sid = cookie_dict['sid'].value

        if 'sid' not in cookie_dict or sid not in sessions:
            sid = secrets.token_urlsafe()  # generate some random token
            session_nonce = secrets.token_urlsafe()
            self.saved_headers = [('Set-Cookie', 'sid=' + sid)]
            sessions[sid] = {}  # the session is initially empty
            nonce_dict[sid] = session_nonce

        return sid

    def do_GET(self):
        sid = self.get_or_create_session()
        if 'username' in sessions[sid]:
            self.send_response_headers_and_body(authenticated_doc.format(username=sessions[sid]['username'], nonce=nonce_dict[sid]))
        else:
            self.send_response_headers_and_body(form_doc.format(nonce=nonce_dict[sid]))

    def do_POST(self):
        sid = self.get_or_create_session()
        nonce = nonce_dict[sid]
        content_length = self.headers['Content-Length']
        body = self.rfile.read(int(content_length))
        post_dict = parse_qs(str(body, 'UTF-8'))

        # Nonce check to defend against CSRF
        if 'nonce' in post_dict:
            post_nonce = post_dict['nonce'][0]
            print("post_nonce: " + post_nonce + "; nonce: " + nonce + "; equality: " + str(nonce == post_nonce))
            if post_nonce != nonce:
                self.send_response_headers_and_body(fail.format(message="Invalid nonce! Go away hackers!"))
                return

        else:
            self.send_response_headers_and_body(fail.format(message="Invalid nonce! Go away hackers!"))
            return

        action = post_dict['action'][0]
        if action == 'login':

            post_user = post_dict['user'][0]
            post_pass = post_dict['pass'][0]

            connection = sqlite3.connect(
                DATABASE_FILE)  # could also be replaced by a connection to a remote sql server, e.g., a mysql instance
            sql = "SELECT username FROM users WHERE username = ? AND password = ?"
            print(f"Executing SQL: {sql}")

            cursor = connection.cursor()
            result = cursor.execute(sql, (post_user, post_pass))
            entry = result.fetchone()
            if entry is None:
                self.send_response_headers_and_body(fail.format(message="Wrong username or password!"))
                return
            else:
                print("Successful login!")
                sessions[sid]['username'] = post_user
                self.redirect('/')
                return

        else:
            sessions[sid] = {}
            self.send_response_headers_and_body(form_doc)
            return

    def send_response_headers_and_body(self, output):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html;charset=utf-8')
        for header, value in self.saved_headers:  # we use saved_headers to store headers for this particular response in get_or_create_session
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(bytes(output, 'UTF-8'))

    def redirect(self, target):
        self.send_response(303)
        self.send_header('Location', target)
        self.end_headers()


# We extend the class MyHandler to define an admin interface. The
# extended class overwrites the base class so that we do not have to
# change anything in the surrounding code.
class MyHandler(MyHandler):
    admin_doc = '''
    <!doctype html>
<html lang="en">
<h1>SEC Intranet - Admin Area</h1>
<a href='/'>Return to home</a>
<table>{rows}</table>
Never store passwords in plain text as we do in this example!
<form method='post' id="database-reset">
    <input type="submit" value="RESET DATABASE" name="action"/>
    <input type="hidden" name="nonce" value="{nonce}">
</form>
<br>
<h3>Create new user:</h3>
<form method="post">
    Username:<br>
    <input type="text" name="username"><br>
    Password:<br>
    <input type="text" name="password"><br>
    Privileges:<br>
    <select name="privileges">
        <option value="all">All</option>
        <option value="user">User</option>
    </select><br>
    <input type="submit" name="action" value="Create user">
    <input type="hidden" name="nonce" value="{nonce}">
</form>
<style>
    table {{
        border: 1px solid black;
        border-collapse: collapse;
    }}

    th, td {{
        border: 1px solid black;
        padding: 3px;
    }}
</style>
'''

    def do_GET(self):
        if self.path != '/admin':
            return super().do_GET()

        sid = self.get_or_create_session()

        if 'username' not in sessions[sid]:
            self.send_response_headers_and_body(fail.format(message="Not logged in! <a href='/'>Return to home</a>"))
            return

        connection = sqlite3.connect(DATABASE_FILE)
        username = sessions[sid]['username']

        sql = "SELECT username FROM users WHERE username = ? AND privileges = 'all';"
        print(f"Executing SQL: {sql}")

        cursor = connection.cursor()
        res = cursor.execute(sql, [username])
        entry = res.fetchone()

        if entry is None:
            self.send_response_headers_and_body(
                fail.format(message="Not enough privileges! <a href='/'>Return to home</a>"))
            return

        res = cursor.execute("SELECT id, username, password, signed_up, privileges FROM users;")
        rows = '<tr> <th>id</th> <th>username</th> <th>password</th> <th>signed_up</th> <th>privileges</th> </tr>'
        for row in res:
            rows += f'<tr> <td>{row[0]}</td> <td>{row[1]}</td> <td>{row[2]}</td> <td>{row[3]}</td> <td>{row[4]}</td> </tr>'

        self.send_response_headers_and_body(self.admin_doc.format(rows=rows, nonce=nonce_dict[sid]))

    def do_POST(self):
        if self.path != '/admin':
            return super().do_POST()

        content_length = self.headers['Content-Length']
        body = self.rfile.read(int(content_length))
        post_dict = parse_qs(str(body, 'UTF-8'))
        sid = self.get_or_create_session()
        nonce = nonce_dict[sid]

        # Nonce check to defend against CSRF
        if 'nonce' in post_dict:
            post_nonce = post_dict['nonce'][0]
            print("post_nonce: " + post_nonce + "; nonce: " + nonce + "; equality: " + str(nonce == post_nonce))
            if post_nonce != nonce:
                self.send_response_headers_and_body(fail.format(message="Invalid nonce! Go away hackers!"))
                return

        else:
            self.send_response_headers_and_body(fail.format(message="Invalid nonce! Go away hackers!"))
            return

        action = post_dict['action'][0]
        if action == 'RESET DATABASE':
            reset_database()
        elif action == 'Create user':
            username = post_dict['username'][0]
            password = post_dict['password'][0]
            privileges = post_dict['privileges'][0]
            self.insert_new_user(username, password, privileges)

        self.redirect('/admin')

    def insert_new_user(self, username, password, privileges):
        print("Attempting to INSERT new user")
        query = "INSERT INTO users(username, password, signed_up, privileges) VALUES (?, ?, ?, ?);"
        now = datetime.now(timezone.utc)
        signed_up = now.strftime("%Y-%m-%d")
        values = (username, password, signed_up, privileges)

        connection = sqlite3.connect(DATABASE_FILE)
        cursor = connection.cursor()
        cursor.execute(query, values)
        connection.commit()
        connection.close()


if __name__ == '__main__':
    server = HTTPServer(('', 8081), MyHandler)
    print("Starting web server on http://localhost:8081/")
    print("Admin interface at http://localhost:8081/admin")
    server.serve_forever()
