# 🚀 FastAPI Authentication Project

A production-ready **FastAPI authentication boilerplate** with JWT-based access & refresh tokens, email token support, SQLAlchemy ORM, and Alembic migrations. Built with scalability and clean architecture in mind.

---

## 📂 Project Structure

```bash
fastapi-auth/
│
├── app/
│   ├── core/              # ⚙️ Configurations & security (settings, password hashing, JWT helpers)
│   ├── db/                # 🗄️ Database session & base model setup
│   ├── models/            # 🧩 SQLAlchemy models (User, RefreshToken, TokenBlacklist, EmailToken)
│   ├── schemas/           # 📜 Pydantic request/response validation models
│   ├── services/          # 🔐 Business logic (authentication, token management)
│   ├── routers/           # 🌐 API endpoints (auth, users)
│   ├── dependencies.py    # 🧷 Shared dependencies (e.g. current_user)
│   └── main.py            # 🚀 FastAPI entrypoint
│
├── alembic/               # 📊 Database migrations
│   └── versions/          # Auto-generated migration files
│
├── tests/                 # ✅ Unit & integration tests
├── scripts/               # 🛠️ Utility scripts (seeding, maintenance)
└── requirements.txt       # 📦 Project dependencies
```

---

## ⚡ Getting Started

### 1️⃣ Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate     # Linux/Mac
venv\Scripts\activate        # Windows
```

### 2️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

### 3️⃣ Run database migrations

```bash
alembic upgrade head
```

### 4️⃣ Start the development server

```bash
uvicorn app.main:app --reload
```

📍 API will be available at: [http://localhost:8000](http://localhost:8000)

---

## 🛠️ Development Notes

* 🔑 **Authentication**: JWT access & refresh tokens, blacklist, email verification tokens.
* 🗄️ **Database**: SQLAlchemy 2.0 ORM with Alembic migrations.
* 📜 **Schemas**: Request/response validation with Pydantic v2.
* 🔐 **Services Layer**: Encapsulates business logic separate from routes.
* ✅ **Tests**: Write & run tests with `pytest`.

---

## 🧪 Running Tests

```bash
pytest
```

---

## 🚧 Next Steps

* Add role-based access control (RBAC)
* Implement background tasks for sending emails
* Introduce rate limiting & advanced security hardening

---
