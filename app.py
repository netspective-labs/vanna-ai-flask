from dotenv import load_dotenv
load_dotenv()

from functools import wraps
from flask import Flask, jsonify, Response, request, redirect, url_for, make_response, render_template_string
import flask
from typing import List, Optional
import ast
import os
from cache import MemoryCache
import openai
from vanna.openai.openai_chat import OpenAI_Chat
from vanna.chromadb.chromadb_vector import ChromaDB_VectorStore
import gevent
from gevent.pywsgi import WSGIServer
from vanna.flask import VannaFlaskApp, Cache
from vanna.base.base import VannaBase
from vanna.flask.auth import AuthInterface , NoAuth
import json

flask_app = Flask(__name__, static_url_path='')

# SETUP
cache = MemoryCache()
# from vanna.local import LocalContext_OpenAI
# vn = LocalContext_OpenAI()

# Set your OpenAI API key
openai.api_key = os.getenv("OPENAI_API_KEY")


class SimplePassword(AuthInterface):
    def __init__(self, db_connection):
        with open('users.json', 'r') as file:
            self.users = json.load(file)['users']
        self.db_connection = db_connection

    def get_user(self, flask_request) -> any:
        return flask_request.cookies.get('user')

    def is_logged_in(self, user: any) -> bool:
        return user is not None

    def override_config_for_user(self, user: any, config: dict) -> dict:
        role = request.cookies.get('role')  # Retrieve the role from the cookie
        if role == 'admin':
            config['show_training_data'] = True
        elif role == 'user':
            config['show_training_data'] = False
        return config

    def login_form(self) -> str:
        message = request.args.get("message", "")
        message_type = request.args.get("message_type", "info")
        return f'''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login</title>
         <style>                       
               .message {{
                text-align: center;
                font-size: 1rem;
                margin-top: 20px;
                color: {'green' if message_type == 'info' else 'red'};
            }}

            </style>
            </head>
            <body>
        <div class="p-4 sm:p-7">
            <div class="text-center">
                <h1 class="block text-2xl font-bold text-gray-800 dark:text-white">Sign in</h1>
            </div>

         <div class="mt-5">
           <!-- Display message -->
                <div class="message {message_type}">{message}</div>
                <form action="/auth/login" method="POST">
                    <div class="grid gap-y-4">
                        <div>
                            <label for="email" class="block text-sm mb-2 dark:text-white">Email address</label>
                            <input type="email" id="email" name="email" class="py-3 px-4 block w-full border border-gray-200 rounded-lg text-sm focus:border-blue-500 focus:ring-blue-500 dark:bg-slate-900 dark:border-gray-700 dark:text-gray-400" required>
                        </div>
                        <div>
                            <label for="password" class="block text-sm mb-2 dark:text-white">Password</label>
                            <input type="password" id="password" name="password" class="py-3 px-4 block w-full border border-gray-200 rounded-lg text-sm focus:border-blue-500 focus:ring-blue-500 dark:bg-slate-900 dark:border-gray-700 dark:text-gray-400" required>
                        </div>
                        <button type="submit" class="w-full py-3 px-4 inline-flex justify-center items-center gap-x-2 text-sm font-semibold rounded-lg border border-transparent bg-blue-600 text-white hover:bg-blue-700">Sign in</button>
                    </div>
                </form>
                <p class="mt-2 text-center text-sm text-gray-600 dark:text-gray-400">
                    <!--Don't have an account? <a href="/register" class="text-blue-600 hover:text-blue-500">Register here</a> -->
                </p>
            </div>
        </div>
        </body>
        </html>

        '''

    def login_handler(self, flask_request) -> str:
        email = flask_request.form['email']
        password = flask_request.form['password']
        with open('users.json', 'r') as file:
            self.users = json.load(file)['users']
            # Find the user by email
        user = next((u for u in self.users if u['email'] == email), None)

        if user:
            # Check if the provided password matches the hashed password stored for the user
            if password == user['password']:
                response = make_response('Logged in as ' + email)
                response.set_cookie('user', email)
                response.set_cookie('role', user['role'])  # Store the user's role in a cookie
                response.headers['Location'] = '/'
                response.status_code = 302
                return response
            else:
                response = make_response(
                    redirect(url_for('login_error', message="Login failed.", message_type="error"))
                )
                return response
        else:
            response = make_response(
                redirect(url_for('login_error', message="User not found", message_type="error"))
            )
            return response

    def callback_handler(self, flask_request) -> str:
        user = flask_request.args['user']
        response = make_response('Logged in as ' + user)
        response.set_cookie('user', user)
        return response

    def logout_handler(self, flask_request) -> str:
        response = make_response(redirect(url_for('login')))
        response.delete_cookie('user')
        response.delete_cookie('role')
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['Location'] = '/'
        return response

    def registration_form(self) -> str:
        message = request.args.get("message", "")
        message_type = request.args.get("message_type", "info")
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Add New User</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f5f5f5;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }}
                .register-container {{
                    background-color: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    max-width: 400px;
                    width: 100%;
                }}
                .register-header {{
                    font-size: 2rem;
                    margin-bottom: 20px;
                    text-align: center;
                }}
                .register-input {{
                    width: 100%;
                    padding: 10px;
                    margin: 10px 0;
                    border-radius: 5px;
                    border: 1px solid #ccc;
                }}
                .register-button {{
                    width: 105%;
                    padding: 10px;
                    background-color: #007bff;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 1rem;
                    margin: 0 auto;
                }}
                .register-button:hover {{
                    background-color: #0056b3;
                }}
               .message {{
                text-align: center;
                font-size: 1rem;
                margin-top: 20px;
                color: {'green' if message_type == 'info' else 'red'};
            }}

            </style>
        </head>
        <body>
            <div class="register-container">
                <div class="register-header">Add New User</div>
                <div>
                <!-- Display message -->
                <div class="message {message_type}">{message}</div>

                <form action="/auth/register" method="POST">
                    <div>
                        <input type="text" placeholder="Full Name" id="name" name="name" class="register-input" />
                    </div>
                    <div>
                        <input type="email" placeholder="Email address" id="email" name="email" class="register-input" />
                    </div>
                    <div>
                        <input type="password" placeholder="Password" id="password" name="password" class="register-input" />
                    </div>                    
                    <div>
                        <button class="register-button">Add User</button>
                    </div>
                </form>

                </div>
                                <div class="flex justify-center mt-2">
  <p class="text-center text-sm text-gray-600 dark:text-gray-400">
    <!-- <a href="auth/logout" class="text-blue-600 hover:text-blue-500">Sign In</a> -->
  </p>
</div>

            </div>

        </body>
        </html>
                """

    def registration_handler(self, flask_request) -> str:
        # Validate the input
        email = flask_request.form['email']
        password = flask_request.form['password']
        name = flask_request.form['name']
        if not name or not email or not password:
            response = make_response(
                redirect(url_for('add_user', message="All fields are required.", message_type="info"))
            )
            return response
            # Hash the password
        # hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        # Path to the JSON file
        users_file = "users.json"
        # Load existing users from the JSON file
        if os.path.exists(users_file):
            with open(users_file, 'r') as file:
                try:
                    data = json.load(file)
                    # Ensure the data is a dictionary and contains a list of users
                    if isinstance(data, dict) and "users" in data:
                        users = data["users"]
                    else:
                        # Initialize with an empty list if the structure is unexpected
                        users = []
                except json.JSONDecodeError:
                    users = []
        else:
            users = []
        # Check if the user already exists
        for user in users:
            if user.get('email') == email:
                response = make_response(
                    redirect(url_for('add_user', message="A user with this email already exists.", message_type="info"))
                )
                return response
        role = 'user'
        new_user = {
            "email": email,
            "password": password,
            "role": role,
            "username": name
        }

        self.users.append(new_user)
        with open('users.json', 'w') as file:
            json.dump({"users": self.users}, file)
        response = make_response(
            redirect(url_for('add_user', message="User registered successfully", message_type="info"))
        )
        # response.set_cookie('user', email)
        # response.set_cookie('role', role)  # Store the user's role in a cookie
        return response


# Database credentials
db_credentials = {
    "host": os.getenv("REMOTE_HOST"),
    "user": os.getenv("REMOTE_UNAME"),
    "password": os.getenv("REMOTE_PASSWD"),
    "database": os.getenv("DB_NAME"),
    "port": os.getenv("PORT"),
}
model = os.getenv("MODEL_NAME")
schema_names = os.getenv("SCHEMA_NAMES")
chroma_path = os.getenv("CHROMA_PATH")

class MyVanna(ChromaDB_VectorStore, OpenAI_Chat):
    def __init__(self, config=None):
        ChromaDB_VectorStore.__init__(self, config=config)
        OpenAI_Chat.__init__(self, config=config)

vn = MyVanna(config={"api_key": openai.api_key, "model": model, "path": chroma_path})
vn.connect_to_postgres(
    host=db_credentials["host"],
    dbname=db_credentials["database"],
    user=db_credentials["user"],
    password=db_credentials["password"],
    port=db_credentials["port"],
)


def get_schema_name(env_var: str) -> Optional[str]:
    """Fetch the schema name from the environment variable."""
    schema_name: Optional[str] = os.getenv(env_var)

    if schema_name:
        print(f"Schema Name from Environment Variable: {schema_name}")
        return schema_name
    else:
        print(f"No schema name found in environment variable: {env_var}")
        return None


def get_default_schema_name(schema_name: Optional[str]) -> Optional[str]:
    """Return the schema name if available."""
    return schema_name


# Fetch the schema name from the environment variable
schema_name: Optional[str] = get_schema_name("SCHEMA_NAME")

# Get the default schema name (since it's a string, it will just return it)
default_schema_name: Optional[str] = get_default_schema_name(schema_name)

# Log the schema name and prepare the SQL query
if default_schema_name:
    print(f"Schema Name: {default_schema_name}")
    sql_query: str = f"SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = '{default_schema_name}'"

    # Train the model with the schema name in the SQL query
    vn.train(
        question=f"What are the table and column names in the '{default_schema_name}' schema?",
        sql=sql_query,
    )
else:
    vn.train(
        question="What is the result of a basic SQL query that returns a constant value?",
        sql="SELECT 1;",
    )
    print("No valid schema name found, setting default initial training data.")

auth = SimplePassword(db_connection='users.json')


class CustomVannaFlask(VannaFlaskApp):
    def __init__(
            self,
            vn: VannaBase,
            cache: Cache = MemoryCache(),
            auth: AuthInterface = NoAuth(),
            debug=False,
            allow_llm_to_see_data=True,
            logo="https://img.vanna.ai/vanna-flask.svg",
            title="English To SQL",
            subtitle="",
            show_training_data=True,
            suggested_questions=True,
            sql=True,
            table=True,
            csv_download=True,
            chart=True,
            redraw_chart=True,
            auto_fix_sql=True,
            ask_results_correct=True,
            followup_questions=True,
            summarization=False,
            function_generation=False,
            index_html_path=None,
            assets_folder=None,
    ):
        # Initialize the parent class VannaFlaskApp
        super().__init__(
            vn,
            cache,
            auth,
            debug,
            allow_llm_to_see_data,
            logo,
            title,
            subtitle,
            show_training_data,
            suggested_questions,
            sql,
            table,
            csv_download,
            chart,
            redraw_chart,
            auto_fix_sql,
            ask_results_correct,
            followup_questions,
            summarization,
            function_generation,
            index_html_path,
            assets_folder,
        )
        self.override_routes()

    def override_routes(self):
        """Override routes with custom implementations."""
        self.flask_app.view_functions.pop("generate_followup_questions", None)

        @self.flask_app.route("/api/v0/generate_followup_questions", methods=["GET"])
        @self.requires_auth
        @self.requires_cache(["df", "question", "sql"])
        def generate_followup_questions(user: any, id: str, df, question, sql):
            """
            Overrides Generate followup questions function by limiting the dataframe rows
            ---
            parameters:
              - name: user
                in: query
              - name: id
                in: query|body
                type: string
                required: true
            responses:
              200:
                schema:
                  type: object
                  properties:
                    type:
                      type: string
                      default: question_list
                    questions:
                      type: array
                      items:
                        type: string
                    header:
                      type: string
            """
            if self.allow_llm_to_see_data:
                followup_questions = self.vn.generate_followup_questions(
                    question=question, sql=sql, df=df.head(100)
                )

                if followup_questions is not None and len(followup_questions) > 5:
                    followup_questions = followup_questions[:5]

                self.cache.set(id=id, field="followup_questions", value=followup_questions)

                return jsonify(
                    {
                        "type": "question_list",
                        "id": id,
                        "questions": followup_questions,
                        "header": "Here are some potential followup questions:",
                    }
                )
            else:
                self.cache.set(id=id, field="followup_questions", value=[])
                return jsonify(
                    {
                        "type": "question_list",
                        "id": id,
                        "questions": [],
                        "header": "Followup Questions can be enabled if you set allow_llm_to_see_data=True",
                    }
                )


ENABLE_VANNA_LOGIN = os.getenv("ENABLE_VANNA_LOGIN")
if ENABLE_VANNA_LOGIN == 'True':
    app = CustomVannaFlask(vn=vn, cache=MemoryCache(), auth=auth)
else:
    app = CustomVannaFlask(vn=vn, cache=MemoryCache())

memory_cache = MemoryCache()
flask_app = app.flask_app


@flask_app.route('/add_user', methods=['GET'])
def add_user():
    user_role = request.cookies.get('role')

    if user_role == 'admin':
        # Redirect non-admin users to a different page or show an error message
        return auth.registration_form()
    else:
        return redirect(url_for('denied', message="Unauthorized access.", message_type="error"))


@flask_app.route('/denied', methods=['GET'])
def denied():
    message = request.args.get("message", "")
    message_type = request.args.get("message_type", "info")
    return f"<h1>{message}</h1>"


@flask_app.route('/auth/register', methods=['POST'])
def handle_register():
    return auth.registration_handler(request)

@flask_app.route('/login-error')
def login_error():
    message = request.args.get("message", "")
    message_type = request.args.get("message_type", "info")
    return f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login Error</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body {{
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                background-color: #f8f9fa;
            }}
            .error-container {{
                background-color: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            }}
            .error-message {{
                color: {'red' if message_type == 'error' else 'green'};
            }}
        </style>
    </head>
    <body>
        <div class="error-container text-center">
            <h2 class="error-message">{message}</h2>            
            <a href="/login" class="btn btn-primary">Go to Login</a>
        </div>
    </body>
    </html>
    '''


if __name__ == '__main__':
    # app.run(debug=True, host='0.0.0.0', port=5000)
    # app.run(host='0.0.0.0') 
    host = '0.0.0.0'  # Replace with your desired IP address
    port = 5000         # Replace with your desired port number

    http_server = WSGIServer((host, port), app.flask_app)
    http_server.serve_forever()
