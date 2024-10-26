# Cryptography Application

A web-based cryptography application that allows users to encrypt and decrypt text using various encryption algorithms, including AES, DES, and RSA. The application provides a user-friendly interface and supports key generation for symmetric encryption methods.

## Table of Contents

- [Features](#features)
- [Technologies Used](#technologies-used)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Backend Setup](#backend-setup)
  - [Frontend Setup](#frontend-setup)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Security Considerations](#security-considerations)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Contact](#contact)
- [Additional Notes](#additional-notes)

---

## Features

- **Encryption Methods**:
  - **AES (Advanced Encryption Standard)**
  - **DES (Data Encryption Standard)**
  - **RSA (Rivest-Shamir-Adleman)**
- **Key Management**:
  - Users can provide their own encryption keys.
  - Key generation feature for AES and DES encryption methods.
- **User Interface**:
  - Simple and intuitive web interface.
  - Real-time error messages and validation.
- **Asynchronous Operations**:
  - Non-blocking encryption and decryption processes.

---

## Technologies Used

- **Frontend**:
  - HTML5
  - CSS3
  - JavaScript (ES6+)
- **Backend**:
  - Python 3.6+
  - Flask
  - Flask-CORS
  - PyCryptodome (for AES and DES encryption)
  - Cryptography (for RSA encryption)
- **Others**:
  - Virtual Environment (`venv`)

---

## Prerequisites

- **Python 3.6 or higher**: Ensure Python is installed on your system.
- **pip**: Python package manager.
- **Node.js and npm** *(Optional)*: For alternative ways to serve the frontend.

---

## Installation

### Backend Setup

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/yourusername/cryptography-app.git
   cd cryptography-app/backend
