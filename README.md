# 🌟 SkyVault - Secure Personal Cloud Storage

<div align="center">
  <img src="static/icons/image-icon.png" alt="SkyVault Logo" width="100" height="100">
  
  [![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
  [![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com)
  [![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)
  [![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
</div>

## 📋 Overview

SkyVault is a modern, secure personal cloud storage system built with Flask. It provides military-grade encryption for your files with an intuitive, glassmorphism-inspired user interface.

### ✨ Key Features

- 🔐 **End-to-End Encryption** - Files encrypted with Fernet symmetric encryption
- 🎨 **Modern UI/UX** - Glassmorphism design with smooth animations
- 📱 **Responsive Design** - Works seamlessly on all devices
- 🚀 **Drag & Drop Upload** - Intuitive file upload experience
- 👤 **User Authentication** - Secure login with password hashing
- 🐳 **Docker Support** - Easy deployment with containerization
- 📊 **File Management** - View, download, and delete files securely

## 🚀 Quick Start

### Installation
1. Repository klonen:
```bash
   git clone https://github.com/DaveMcBeer/SkyVault_Technikum_Wien
   cd SkyVault_Technikum_Wien
```

2. Konfiguration anlegen:
```bash
   cp .env.example .env
   # .env öffnen und SECRET_KEY sowie ENCRYPTION_KEY eintragen
```

3. Keys generieren:
```bash
   # SECRET_KEY
   python -c "import secrets; print(secrets.token_hex(32))"

   # ENCRYPTION_KEY
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**Wenn Docker verwendet wird, diesen Schritt überspringen!**
### (Ohne Docker) **Create virtual environment**
Prerequisites
- Python 3.8+
- pip
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

 **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```
   
 **Run the application**
   ```bash
   python app.py
   ```

## 🐳 (Mit Docker) Start Docker Container
```bash
   docker-compose up
```

6. **Access the application**
   Open your browser and navigate to `http://127.0.0.1:5000`

## 🎨 UI Features

- **Glassmorphism Design** - Modern transparent cards with backdrop blur
- **Smooth Animations** - CSS transitions and keyframe animations
- **Interactive Elements** - Drag & drop, hover effects, loading states
- **Responsive Layout** - Mobile-first design approach
- **Dark Theme** - Elegant gradient backgrounds

## 🔒 Security Features

- **File Encryption** - All files encrypted using Fernet symmetric encryption
- **Password Hashing** - Secure password storage with bcrypt
- **Session Management** - Flask-Login for secure user sessions
- **Input Validation** - Server-side validation for all inputs

## 🚀 Deployment Options

### GitHub Pages (Static Demo)
- Fork this repository
- Enable GitHub Pages in repository settings
- Access via `https://yourusername.github.io/SkyVault`

### Heroku
```bash
# Install Heroku CLI and login
heroku create your-app-name
git push heroku main
```

### Railway
```bash
# Connect your GitHub repository to Railway
# Deploy with one click
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Flask** - Micro web framework
- **Bootstrap** - UI components and responsive design
- **Bootstrap Icons** - Beautiful icon library
- **Cryptography** - File encryption capabilities

## 📞 Support

If you have any questions or need help, please:
- Open an issue on GitHub
- Check the documentation
- Contact the maintainers

---

<div align="center">
  Made with ❤️ by Priyanshu K Sharma
  
  ⭐ Star this repository if you found it helpful!
</div>
