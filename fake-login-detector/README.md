# Fake Login Page Detector

A web-based phishing detection tool that identifies suspicious login pages by comparing them with genuine pages and presenting explainable evidence.

## Features

- Clone-likelihood score and risk verdict
- Genuine-versus-suspect page comparison
- Screenshot and visual difference analysis
- Domain, HTML, form-action, and asset evidence
- JSON and PDF report exports

## Technology Stack

- **Backend:** Python, FastAPI, Playwright
- **Frontend:** HTML, CSS, JavaScript
- **Analysis:** Domain, form, DOM, visual, and asset analyzers
- **Testing:** pytest

## Requirements

- Python 3.13 recommended
- Git
- Internet access to install Python dependencies and the Playwright browser

## Setup on Windows

### 1. Clone the repository

```bat
git clone -b integration/shared-fetcher https://github.com/shivahiremath001/fakeLoginPageDetector.git
cd fakeLoginPageDetector
```

### 2. Create and activate a virtual environment

```bat
cd backend
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies and the browser

```bat
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m playwright install chromium
```

### 4. Start the backend

From the `backend` directory, run:

```bat
python -m uvicorn app.main:app
```

The API will be available at:

- API: http://127.0.0.1:8000
- API documentation: http://127.0.0.1:8000/docs

Keep this terminal open.

### 5. Start the frontend

Open a second terminal:

```bat
cd fakeLoginPageDetector\frontend
python -m http.server 8080
```

Open http://localhost:8080 in your browser.

Keep this terminal open as well.

### 6. Start the local demo pages

Open a third terminal from the repository root:

```bat
cd fakeLoginPageDetector
python testpages\serve_all.py
```

The current demo server provides these local pages:

- Genuine login page: http://localhost:5001/login
- Clone login page: http://localhost:5002/login
- Unrelated page: http://localhost:5003/login
- Form target: http://localhost:5006/submit

Keep this terminal open while testing.

## Run the tests

Open a terminal and run:

```bat
cd fakeLoginPageDetector\backend
.venv\Scripts\activate
python -m pytest tests\unit -q
```

## Project Structure

```text
fakeLoginPageDetector/
├── backend/
│   ├── app/
│   │   ├── analyzers/
│   │   ├── utils/
│   │   ├── fetcher.py
│   │   ├── main.py
│   │   ├── orchestrator.py
│   │   └── scoring.py
│   ├── config/
│   ├── tests/
│   └── requirements.txt
├── frontend/
│   ├── images/
│   ├── index.html
│   ├── Styles.css
│   └── JavaScript modules
├── shared/
│   └── domain_test_vectors.json
└── testpages/
    └── serve_all.py
```

## Safety Notice

Use this tool only with URLs you are authorized to test. The local demo pages are provided for controlled testing. A risk score is an indicator, not a guarantee that a page is safe or malicious.

## Current Test Status

The project unit tests passed locally: **143 passed**.
