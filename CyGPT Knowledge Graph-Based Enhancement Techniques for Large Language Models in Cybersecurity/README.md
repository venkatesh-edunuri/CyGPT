# CyGPT — Knowledge Graph-Based Enhancement for LLMs in Cybersecurity

An AI-powered cybersecurity assistant combining Large Language Models with Knowledge Graphs for accurate, hallucination-reduced responses.

---

## Stack
- **Backend:** Python 3.11, Django 4.2, MySQL
- **AI:** OpenAI GPT-3.5-turbo
- **Frontend:** HTML5, CSS3, Bootstrap 5, Tailwind CSS, Vanilla JS, Chart.js
- **Architecture:** Knowledge Graph + Joint Reasoning Engine

---

## Quick Setup

### 1. Prerequisites
- Python 3.11.9
- MySQL 8.0+
- OpenAI API key

### 2. Clone & Install
```bash
git clone <repo-url>
cd cygpt
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Environment Variables
```bash
cp .env.example .env
# Edit .env with your values:
# SECRET_KEY, DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, OPENAI_API_KEY
```

### 4. MySQL Database
```sql
CREATE DATABASE cygpt_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'cygpt_user'@'localhost' IDENTIFIED BY 'yourpassword';
GRANT ALL PRIVILEGES ON cygpt_db.* TO 'cygpt_user'@'localhost';
FLUSH PRIVILEGES;
```

### 5. Run Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

### 6. Seed Cybersecurity Knowledge Data
```bash
python manage.py seed_knowledge
```

### 7. Create Superuser (Admin)
```bash
python manage.py createsuperuser
# Then set role to admin via Django admin or shell:
# python manage.py shell
# >>> from users.models import CustomUser
# >>> u = CustomUser.objects.get(email='admin@example.com')
# >>> u.role = 'admin'; u.save()
```

### 8. Collect Static Files (Production)
```bash
python manage.py collectstatic
```

### 9. Run Development Server
```bash
python manage.py runserver
```

Visit: http://127.0.0.1:8000

---

## Modules

| Module | Path | Description |
|--------|------|-------------|
| Users | `/users/` | Auth, registration, profiles |
| Chatbot | `/chatbot/` | AI chat, query history |
| Knowledge Graph | `/knowledge/` | Threat database (admin) |
| Admin Panel | `/adminpanel/` | System management |
| Django Admin | `/admin/` | Low-level admin |

---

## Joint Reasoning Chain (8 Steps)

1. Receive user query
2. Search MySQL knowledge graph
3. Retrieve relevant cybersecurity data
4. Construct enhanced prompt with KG context
5. Send enhanced prompt to OpenAI GPT
6. Receive LLM response
7. Run evaluation module (relevance, hallucination, confidence)
8. Display verified response to user

---

## Project Structure

```
cygpt/
├── manage.py
├── requirements.txt
├── .env.example
├── cygpt/          # Django project settings, URLs
├── users/          # Custom user model, auth views
├── chatbot/        # Chat views, query models
├── knowledgegraph/ # CyberKnowledge model + CRUD
├── evaluation/     # Response evaluation model
├── adminpanel/     # Admin dashboard views
├── services/       # OpenAI service + reasoning engine
├── templates/      # All HTML templates
└── static/         # CSS, JS, images
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Django secret key |
| `DEBUG` | True/False |
| `DB_NAME` | MySQL database name |
| `DB_USER` | MySQL username |
| `DB_PASSWORD` | MySQL password |
| `DB_HOST` | MySQL host (default: localhost) |
| `DB_PORT` | MySQL port (default: 3306) |
| `OPENAI_API_KEY` | Your OpenAI API key |

---

## Production Deployment

```bash
# Set DEBUG=False in .env
# Set ALLOWED_HOSTS appropriately
gunicorn cygpt.wsgi:application --bind 0.0.0.0:8000
```

---

## Demo Mode

If `OPENAI_API_KEY` is not set, the system runs in **Demo Mode** — all features work except live AI responses, which show a placeholder explaining the missing key.
