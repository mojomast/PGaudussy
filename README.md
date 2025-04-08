# 🔐 PGaudussy

<div align="center">
  
![Version](https://img.shields.io/badge/version-1.0.0-blue.svg?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.13+-green.svg?style=for-the-badge&logo=python)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Compatible-blue.svg?style=for-the-badge&logo=postgresql)
![License](https://img.shields.io/badge/license-MIT-orange.svg?style=for-the-badge)

</div>

<div align="center">
  <h3>A powerful PostgreSQL database permissions auditing and management tool</h3>
  <h4>Created by Kyle Durepos</h4>
</div>

<p align="center">
  <img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/postgresql/postgresql-original-wordmark.svg" alt="postgresql" width="120" height="120"/>
</p>

---

## 🌟 Overview

PGaudussy is a comprehensive PostgreSQL database permissions auditing and management tool designed to help database administrators identify security risks, enforce best practices, and maintain secure database environments. With an intuitive interface and powerful features, PGaudussy simplifies the complex task of managing database permissions.

This is my first serious software project, born from the need to efficiently manage database permissions across multiple PostgreSQL instances in enterprise environments.

## ✨ Features

- **🔍 Comprehensive Auditing**: Analyze permissions at database, schema, table, and role levels
- **⚠️ Risk Detection**: Identify potentially risky permissions and security vulnerabilities
- **🛡️ Permission Management**: Enforce best practices and security policies
- **💾 Backup & Restore**: Safely backup and restore databases before making changes
- **🔄 Interactive Mode**: User-friendly interactive menu for easy navigation
- **📊 Detailed Reports**: Generate comprehensive audit reports
- **🔐 Authentication**: Seamless integration with pg_service.conf for secure authentication
- **🚀 Safety Features**: Dry-run mode and rollback capability to prevent unwanted changes

## 🚀 Getting Started

### Prerequisites

- Python 3.13+
- PostgreSQL client tools (psql, pg_dump, pg_restore)
- A valid pg_service.conf file

### Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/pgaudussy.git
   cd pgaudussy
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Configuration

PGaudussy uses pg_service.conf for PostgreSQL connection information. This file can be located in your project directory or your home directory.

Example pg_service.conf:
```ini
[service_name]
host=localhost
port=5432
dbname=your_database
user=your_username
password=your_password
sslmode=require
```

## 🖥️ Usage

### Interactive Mode

The easiest way to use PGaudussy is through its interactive menu:

```bash
python menu.py
```

### Command Line Interface

For advanced users or automation:

```bash
python dbaudit.py --service your_service_name audit
```

Available commands:

- `audit`: Audit database permissions and generate a report
- `backup`: Backup database before making permission changes
- `restore`: Restore database from a backup
- `fix`: Fix permissions according to best practices or templates

For more options:

```bash
python dbaudit.py --help
```

## 📋 Example Workflow

1. Create or select a PostgreSQL service
2. Run a database audit to identify permission issues
3. Review the audit results
4. Backup the database before making changes
5. Apply recommended fixes or custom permission changes
6. Verify changes with another audit

## 🛠️ Advanced Usage

### Custom Audit Rules

You can customize audit rules by modifying the configuration files in the `config` directory.

### Integration with CI/CD

PGaudussy can be integrated into CI/CD pipelines to ensure database permissions comply with security policies before deployment.

## 📊 Sample Output

```
╭────────────────────────────────────────────╮
│ PostgreSQL Database Permissions Audit Tool │
╰───────────── Audit Results ────────────────╯

Database: production_db
Service: prod_service

Issues Found:
✘ Public schema accessible to all users
✘ PUBLIC role has excessive privileges on 3 tables
✘ User 'app_user' has superuser privileges
✘ Weak password policies detected

Recommendations:
✓ Revoke PUBLIC privileges on sensitive tables
✓ Remove superuser privileges from application users
✓ Implement row-level security on customer_data table
✓ Enable password policy enforcement
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- The PostgreSQL community for their excellent documentation
- All the open-source contributors whose libraries made this project possible

---

<div align="center">
  <p>Made with ❤️ by Kyle Durepos</p>
  <p>© 2025 Kyle Durepos. All rights reserved.</p>
</div>
