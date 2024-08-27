from dotenv import load_dotenv
from typing import List, Optional
load_dotenv()

from functools import wraps
from flask import Flask, jsonify, Response, request, redirect, url_for
import flask
import os
import ast
from cache import MemoryCache
import openai
from vanna.openai.openai_chat import OpenAI_Chat
from vanna.chromadb.chromadb_vector import ChromaDB_VectorStore
import gevent
from gevent.pywsgi import WSGIServer
from vanna.flask import VannaFlaskApp


flask_app = Flask(__name__, static_url_path='')

# SETUP
cache = MemoryCache()
# from vanna.local import LocalContext_OpenAI
# vn = LocalContext_OpenAI()

# Set your OpenAI API key
openai.api_key = os.getenv("OPENAI_API_KEY")

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


def get_schema_names(env_var: str) -> Optional[List[str]]:
    """Fetch and parse the schema names from the environment variable."""
    schema_names_str: Optional[str] = os.getenv(env_var)
    if schema_names_str:
        try:
            print(schema_names_str)
            schema_names_list: List[str] = ast.literal_eval(schema_names_str)
            return schema_names_list
        except (ValueError, SyntaxError):
            print(f"Error parsing the schema names from {env_var}")
            return None
    return None


def get_default_schema_name(schema_names: Optional[List[str]]) -> Optional[str]:
    """Return the first schema name from the list if available."""
    if schema_names:
        return schema_names[0]
    return None


# Fetch the schema names from the environment variable
schema_names: Optional[List[str]] = get_schema_names("SCHEMA_NAMES")

# Get the default schema name
default_schema_name: Optional[str] = get_default_schema_name(schema_names)

# Log the schema name and prepare the SQL query
if default_schema_name:
    print(f"Schema Name: {default_schema_name}")
    sql_query: str = f"SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = {default_schema_name}"
    print(f"Executing SQL Query: {sql_query}")

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

app = VannaFlaskApp(
    vn=vn,
    allow_llm_to_see_data=True,
    title="English To SQL",
    subtitle="",
    show_training_data=True,
    sql=True,
    table=True,
    chart=True,
    summarization=False,
    ask_results_correct=True,
    debug=False,
)

memory_cache = MemoryCache()


class CustomVannaFlaskApp(VannaFlaskApp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.flask_app = flask_app
        self.add_routes()

    # -------------------------------------------------------------------------------
    # NO NEED TO CHANGE ANYTHING BELOW THIS LINE
    def requires_cache(fields):
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                id = request.args.get("id")

                if id is None:
                    return jsonify({"type": "error", "error": "No id provided"})

                for field in fields:
                    if cache.get(id=id, field=field) is None:
                        return jsonify({"type": "error", "error": f"No {field} found"})

                field_values = {
                    field: cache.get(id=id, field=field) for field in fields
                }

                # Add the id to the field_values
                field_values["id"] = id

                return f(*args, **field_values, **kwargs)

            return decorated

        return decorator

    def add_routes(self):
        @self.flask_app.route("/api/v0/generate_questions", methods=["GET"])
        def generate_questions():
            return jsonify(
                {
                    "type": "question_list",
                    "questions": vn.generate_questions(),
                    "header": "Here are some questions you can ask:",
                }
            )

        @self.flask_app.route("/api/v0/generate_sql", methods=["GET"])
        def generate_sql():
            question = flask.request.args.get("question")

            if question is None:
                return jsonify({"type": "error", "error": "No question provided"})

            id = cache.generate_id(question=question)
            sql = vn.generate_sql(question=question, allow_llm_to_see_data=True)

            cache.set(id=id, field="question", value=question)
            cache.set(id=id, field="sql", value=sql)

            return jsonify(
                {
                    "type": "sql",
                    "id": id,
                    "text": sql,
                }
            )

        @self.flask_app.route("/api/v0/run_sql", methods=["GET"])
        @self.requires_cache(["sql"])
        def run_sql(id: str, sql: str):
            try:
                df = vn.run_sql(sql=sql)

                cache.set(id=id, field="df", value=df)

                return jsonify(
                    {
                        "type": "df",
                        "id": id,
                        "df": df.head(10).to_json(orient="records"),
                    }
                )

            except Exception as e:
                return jsonify({"type": "error", "error": str(e)})

        @self.flask_app.route("/api/v0/download_csv", methods=["GET"])
        @self.requires_cache(["df"])
        def download_csv(id: str, df):
            csv = df.to_csv()

            return Response(
                csv,
                mimetype="text/csv",
                headers={"Content-disposition": f"attachment; filename={id}.csv"},
            )

        @self.flask_app.route("/api/v0/generate_plotly_figure", methods=["GET"])
        @self.requires_cache(["df", "question", "sql"])
        def generate_plotly_figure(id: str, df, question, sql):
            try:
                code = vn.generate_plotly_code(
                    question=question,
                    sql=sql,
                    df_metadata=f"Running df.dtypes gives:\n {df.dtypes}",
                )
                fig = vn.get_plotly_figure(plotly_code=code, df=df, dark_mode=False)
                fig_json = fig.to_json()

                cache.set(id=id, field="fig_json", value=fig_json)

                return jsonify(
                    {
                        "type": "plotly_figure",
                        "id": id,
                        "fig": fig_json,
                    }
                )
            except Exception as e:
                # Print the stack trace
                import traceback

                traceback.print_exc()

                return jsonify({"type": "error", "error": str(e)})

        @self.flask_app.route("/api/v0/get_training_data", methods=["GET"])
        def get_training_data():
            df = vn.get_training_data()
            return jsonify(
                {
                    "type": "df",
                    "id": "training_data",
                    "df": df.head(25).to_json(orient="records"),
                }
            )

        @self.flask_app.route("/api/v0/remove_training_data", methods=["POST"])
        def remove_training_data():
            # Get id from the JSON body
            id = flask.request.json.get("id")

            if id is None:
                return jsonify({"type": "error", "error": "No id provided"})

            if vn.remove_training_data(id=id):
                return jsonify({"success": True})
            else:
                return jsonify(
                    {"type": "error", "error": "Couldn't remove training data"}
                )

        @self.flask_app.route("/api/v0/train", methods=["POST"])
        def add_training_data():
            question = flask.request.json.get("question")
            sql = flask.request.json.get("sql")
            ddl = flask.request.json.get("ddl")
            documentation = flask.request.json.get("documentation")

            try:
                id = vn.train(
                    question=question, sql=sql, ddl=ddl, documentation=documentation
                )

                return jsonify({"id": id})
            except Exception as e:
                return jsonify({"type": "error", "error": str(e)})

        @self.flask_app.route("/api/v0/generate_followup_questions", methods=["GET"])
        @self.requires_cache(["df", "question"])
        def generate_followup_questions(id: str, df, question, sql):
            followup_questions = vn.generate_followup_questions(
                question=question, sql=sql, df=df
            )

            cache.set(id=id, field="followup_questions", value=followup_questions)

            return jsonify(
                {
                    "type": "question_list",
                    "id": id,
                    "questions": followup_questions,
                    "header": "Here are some followup questions you can ask:",
                }
            )

        @self.flask_app.route("/api/v0/load_question", methods=["GET"])
        @self.requires_cache(
            ["question", "sql", "df", "fig_json", "followup_questions"]
        )
        def load_question(id: str, question, sql, df, fig_json, followup_questions):
            try:
                return jsonify(
                    {
                        "type": "question_cache",
                        "id": id,
                        "question": question,
                        "sql": sql,
                        "df": df.head(10).to_json(orient="records"),
                        "fig": fig_json,
                        "followup_questions": followup_questions,
                    }
                )

            except Exception as e:
                return jsonify({"type": "error", "error": str(e)})

        @self.flask_app.route("/api/v0/get_question_history", methods=["GET"])
        def get_question_history():
            return jsonify(
                {
                    "type": "question_history",
                    "questions": cache.get_all(field_list=["question"]),
                }
            )


if __name__ == "__main__":
    host = "0.0.0.0"  # Replace with your desired IP address
    port = 5000  # Replace with your desired port number

    http_server = WSGIServer((host, port), app.flask_app)

    http_server.serve_forever()