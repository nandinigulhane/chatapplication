from db import mysql
from flask import Flask, request, render_template, redirect, url_for,session, jsonify
import requests, os

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

SECRET_FILE = "client_secret.json"
SCOPES = ['https://www.googleapis.com/auth/userinfo.email', 'openid']

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
app.config["MYSQL_HOST"] = os.environ.get("MYSQL_HOST")
app.config["MYSQL_USER"] = os.environ.get("MYSQL_USER")
app.config["MYSQL_PASSWORD"] = os.environ.get("MYSQL_PASSWORD")
app.config["MYSQL_DB"] = "chatapp"

def cred_to_dict(credentials):
    return {'token' : credentials.token,
            'refresh_token' : credentials.refresh_token,
            'token_uri' : credentials.token_uri,
            'client_id' : credentials.client_id,
            'client_secret' : credentials.client_secret,
            'scopes' : credentials.scopes}


@app.route('/')
def index():
    return """
        <a href='/login'>Login</a>
    """

@app.route('/login/callback')
def callback():
    state = session['state']
    flow = Flow.from_client_secrets_file(SECRET_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('callback',_external=True)

    flow.fetch_token(authorization_response=request.url)
    session['credentials'] = cred_to_dict(flow.credentials)

    user_info_service = build('oauth2', 'v2', credentials=flow.credentials)
    user_info = user_info_service.userinfo().get().execute()
    return """
    <p>Logged in as {}<p>
    """.format(user_info['email'])
    


@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(SECRET_FILE, scopes=SCOPES)
    flow.redirect_uri = url_for('callback', _external=True)
    auth_url, state = flow.authorization_url(access_type='offline',include_granted_scopes='true')

    session['state'] = state
    return redirect(auth_url)


if __name__ == "__main__":
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    mysql.init_app(app)
    app.run(debug=True)