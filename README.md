# Hackverse-An-Ethical-Hacking-Simulation-Game
An Ethical Hacking Simulation Game

# FastAPI + MongoDB Secure Web App

This project is a secure full-stack web application built using **FastAPI** for the backend, **MongoDB** for the database, and **HTML served locally** for the frontend. It demonstrates how a frontend can securely communicate with a backend API.

---

##  How to Run the Project

### 1. Setup Instructions

- **Unzip** the project folder.
- Open the folder in **VS Code** or any IDE with **Python 3.11+** installed.
- Make sure **all project files are in a single directory**.

---

### 2. Install Required Packages

Use the terminal to install the necessary dependencies. This ensures the backend can run properly and securely.

---

### 3. Start the Servers

Open **two terminal windows or use a split terminal**.

- In **Terminal 1**, run the backend FastAPI server.
  - For **Windows**: use `py -3.11 -m uvicorn main:app --reload`
  - For **macOS/Linux**: use `uvicorn main:app`

- In **Terminal 2**, run the frontend static file server:
  - `python -m http.server 8080`

---

### 4. View the App

After starting both servers, open a browser and go to:
 - https://localhost:8080

