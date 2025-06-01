# FastAPI REST API Project

This project provides two main options for running and testing a REST API for user registration, login, logout, restaurant search, and transaction listing:

## Option 1: Jupyter/Colab Notebook (`fastapi_notebook.ipynb`)
- All code and explanations are in a single notebook.
- Designed for interactive exploration and step-by-step execution.
- Automated tests are included as notebook cells, but pytest cannot run directly on `.ipynb` files.
- To run tests, call the test functions directly in notebook cells.

## Option 2: Python Script (`main.py` and `test_main.py`)
**Recommended for running automated tests**

### How to Use This Option
1. **Install dependencies**
   - You need Python 3.8+ installed.
   - Install required packages:
     ```powershell
     pip install fastapi uvicorn sqlalchemy passlib[bcrypt] python-jose httpx pytest
     ```
2. **Run the API server**
   - Start the FastAPI server:
     ```powershell
     uvicorn main:app --reload
     ```
   - The API will be available at http://127.0.0.1:8000

3. **Run the automated tests**
   - In a separate terminal, run:
     ```powershell
     pytest test_main.py
     ```
   - This will execute all tests in `test_main.py` and report results.

### Features
- SQLite database for persistence (created as `test.db` in the project folder).
- JWT authentication for protected endpoints.
- `/register`, `/token`, `/logout`, `/restaurants`, and `/transactions` endpoints.
- Automated tests for all main features.

---

**Note:**
- The `.py` option is best for local development, debugging, and running automated tests.
- The notebook option is best for learning, step-by-step execution, and interactive exploration.
