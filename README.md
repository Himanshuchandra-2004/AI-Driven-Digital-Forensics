# AI-Driven Digital Forensics — Network Forensics

> **B.Tech Computer Science / Cyber Security Academic Project**

An AI-driven network forensics system that helps investigators analyse large volumes of network traffic, detect anomalies and threats using machine learning, extract forensic evidence, correlate related events, maintain evidence integrity, and generate comprehensive forensic reports.

---

## 🏗 Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌──────────────┐
│   React + Vite  │────▶│   FastAPI + ML   │────▶│  PostgreSQL   │
│   Frontend      │     │   Backend        │     │  or SQLite    │
│   :5173         │     │   :8000          │     │               │
└─────────────────┘     └─────────────────┘     └──────────────┘
```

### Complete Workflow Pipeline

```
DATA COLLECTION → PREPROCESSING → FEATURE EXTRACTION
    → ISOLATION FOREST (Anomaly Detection)
    → RANDOM FOREST (Threat Classification)
    → EVIDENCE EXTRACTION → EVIDENCE CORRELATION
    → RISK ASSESSMENT → SECURE HASHING (SHA-256)
    → CHAIN OF CUSTODY → FORENSIC REPORTING
    → INVESTIGATOR DASHBOARD
```

---

## 🛠 Technology Stack

| Component | Technology |
|-----------|-----------|
| Frontend | React 18 + TypeScript + Vite + Tailwind CSS v3 |
| Charts | Recharts |
| Graph Viz | React Force Graph 2D |
| Backend | Python 3.11+ + FastAPI |
| ORM | SQLAlchemy 2.0 + Alembic |
| Database | PostgreSQL 15 (production) / SQLite (local dev) |
| ML | scikit-learn + pandas + numpy + joblib |
| Auth | JWT (python-jose) + bcrypt |
| PDF Reports | ReportLab |
| Container | Docker + Docker Compose |

---

## 📁 Project Structure

```
Digital Forensics/
├── backend/
│   ├── app/
│   │   ├── api/              # FastAPI route handlers (9 routers)
│   │   ├── core/             # Config, DB, auth, dependencies
│   │   ├── models/           # SQLAlchemy ORM models (12 tables)
│   │   ├── schemas/          # Pydantic request/response schemas
│   │   ├── services/         # Business logic (analysis, risk, hash, reports)
│   │   └── main.py           # Application entry point
│   ├── alembic/              # Database migrations
│   ├── tests/                # Pytest test suite
│   ├── uploads/              # Uploaded data files
│   ├── reports/              # Generated PDF reports
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── api/              # Axios API client
│       ├── components/       # Reusable UI components
│       ├── context/          # React auth context
│       ├── pages/            # Route pages (7 pages)
│       ├── types/            # TypeScript interfaces
│       └── App.tsx           # Router setup
├── ml/
│   ├── data/                 # Raw + processed datasets
│   ├── preprocessing/        # Data cleaning + feature pipeline
│   ├── training/             # Model training scripts
│   ├── inference/            # Inference predictor
│   ├── evaluation/           # Metrics evaluation
│   ├── models/               # Saved model artifacts
│   └── demo/                 # Synthetic data generator
├── scripts/
│   ├── init_db.py            # Database initialization
│   ├── train_on_demo.py      # Train models on synthetic data
│   └── setup_local.sh        # One-command local setup
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## 🚀 Quick Start (Local Development)

### Prerequisites

- Python 3.11+
- Node.js 18+
- npm 9+

### Option 1: Automated Setup

```bash
cd "Digital Forensics"
chmod +x scripts/setup_local.sh
./scripts/setup_local.sh
```

### Option 2: Manual Setup

```bash
# 1. Install backend dependencies
cd backend
pip install -r requirements.txt

# 2. Train ML models (on synthetic demo data)
cd ..
python -m scripts.train_on_demo

# 3. Initialize database & seed users
python -m scripts.init_db

# 4. Start backend
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 5. (In another terminal) Install & start frontend
cd frontend
npm install
npm run dev
```

### Default Login Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | Admin |
| `investigator` | `invest123` | Investigator |

### Access Points

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **API Docs (Swagger)**: http://localhost:8000/docs
- **API Docs (ReDoc)**: http://localhost:8000/redoc

---

## 🐳 Docker Deployment

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env with secure passwords

# Build and start all services
docker compose up --build
```

---

## 🤖 ML Models

### Dataset: CICIDS2017

The system is designed for the [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) dataset.

For quick start without downloading the full dataset (~1GB), the system includes a **synthetic demo data generator** that produces realistic network flow data.

### Isolation Forest (Anomaly Detection)
- Unsupervised anomaly detection
- Contamination: 10%
- 200 estimators
- Flags unusual network patterns regardless of known attack signatures

### Random Forest (Threat Classification)
- Supervised multi-class classification
- 200 estimators, max_depth=20
- Class-balanced weighting for handling data imbalance
- Classifies threats: DoS, DDoS, Bot, PortScan, Brute Force, Web Attack

### 37 Network Flow Features Used
- Flow Duration, Packet Counts, Packet Lengths, Bytes/s, Packets/s
- Inter-Arrival Times (IAT), Flag Counts (SYN, FIN, RST, ACK, PSH, URG)
- Window Sizes, Active/Idle Times, Down/Up Ratio

> Note: Source/Destination IPs are preserved as metadata for evidence correlation but are NOT used as ML features (to avoid data leakage).

---

## 🔒 Security Features

- **Authentication**: JWT tokens with configurable expiry
- **Authorization**: Role-based access (Admin > Investigator > Viewer)
- **Password Security**: bcrypt hashing via passlib
- **Evidence Integrity**: SHA-256 hash chaining (tamper-evident)
- **Chain of Custody**: Complete audit trail for all evidence actions
- **Upload Security**: Extension whitelist, size limits, sanitized filenames
- **SQL Injection**: ORM-only queries (no raw SQL)
- **CORS**: Configurable origin whitelist

---

## 📊 Risk Scoring Formula

```
risk_score = (
    0.30 × normalized_anomaly_score +      # 0-100 from Isolation Forest
    0.25 × threat_confidence +              # 0-100 from Random Forest
    0.20 × threat_severity_weight +         # Based on threat category
    0.15 × frequency_score +               # Repeated suspicious activity
    0.10 × correlation_count_score         # Number of correlated events
)
```

| Risk Score | Severity |
|-----------|----------|
| 0–25 | LOW |
| 26–50 | MEDIUM |
| 51–75 | HIGH |
| 76–100 | CRITICAL |

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|---------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login, get JWT token |
| GET | `/api/auth/me` | Get current user info |
| GET/POST | `/api/cases` | List / create cases |
| GET/PUT/DELETE | `/api/cases/{id}` | Case CRUD |
| POST | `/api/cases/{id}/upload` | Upload network data |
| POST | `/api/cases/{id}/analyze` | Start ML analysis |
| GET | `/api/cases/{id}/threats` | List threat detections |
| GET | `/api/cases/{id}/anomalies` | List anomaly detections |
| GET | `/api/cases/{id}/evidence` | List extracted evidence |
| POST | `/api/evidence/{id}/verify` | Verify evidence integrity |
| GET | `/api/evidence/{id}/custody` | View chain of custody |
| GET | `/api/cases/{id}/incidents` | List correlated incidents |
| POST | `/api/cases/{id}/report` | Generate forensic report |
| GET | `/api/dashboard/stats` | Dashboard statistics |
| GET | `/api/models` | ML model metadata |
| POST | `/api/demo/load` | Load demo case |
| GET | `/api/health` | Health check |

---

## 🧪 Testing

```bash
# Backend tests
cd backend
python -m pytest tests/ -v

# Frontend build check
cd frontend
npm run build
```

---

## 📄 License

This is an academic project for educational purposes.

---

## 👤 Author

B.Tech Computer Science / Cyber Security Project
