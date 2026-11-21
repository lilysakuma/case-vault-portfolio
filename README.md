# Case Vault — Cybersecurity Incident Manager

A database-driven web application for tracking and managing cybersecurity incidents, developed as a collaborative database systems course project.

## Overview

Case Vault helps organize cybersecurity incidents and their related information in one place. The application uses a Flask backend, a SQLite relational database, and an HTML/CSS interface.

## Features

- Create, view, edit, and delete cybersecurity incidents
- Track incident status and severity
- Record evidence associated with incidents
- Create and manage incident-related tasks
- Associate incidents with assets and tags
- View related incidents and vulnerability information

## Technologies

- **Python** — Backend application logic
- **Flask** — Web framework and routing
- **SQLite** — Relational database
- **SQL** — Database schema, queries, and relationships
- **HTML/CSS** — User interface

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/lilysakuma/case-vault-portfolio.git
cd case-vault-portfolio
```

### 2. Install dependencies

```bash
python3 -m pip install -r requirements.txt
```

### 3. Run the application

```bash
python3 app.py
```

Open `http://127.0.0.1:5000/init` to initialize the local database with sample data, then use the application at `http://127.0.0.1:5000/`.

**Important:** The initialization route resets the local database and deletes existing records. This project is intended for local educational use, not production deployment.

## Project Structure

```text
case-vault-portfolio/
├── app.py
├── schema.sql
├── seed.sql
├── requirements.txt
├── templates/
├── static/
├── README.md
└── Database Project Documentation.pdf
```

## Team Project and Contributions

Originally developed for COP 4710 as a collaborative project by:

- Lily Sakuma
- Kathrine Lu
- Mia LaRocca
- Brandon Mealey

My contributions involved collaborative work across the database, backend, frontend, and project documentation.

This repository is my personal portfolio copy of the original group project, maintained separately for documentation, cleanup, and improvements.

## Project Documentation

See [Database Project Documentation.pdf](Database%20Project%20Documentation.pdf) for the original project report, including database design and implementation details.

## Future Improvements

- Add automated tests
- Improve form validation and error handling
- Replace the database-reset route with a safer initialization workflow
- Add authentication and authorization
- Prepare the application for secure deployment