# Document Scanning and Matching System with Credits

## Project Overview
This project is a document scanning and matching system where users can upload documents and check if they match with existing documents.  
Each user has **20 free scans every day**, but if they need more, they can ask the admin for extra credits.  

---

## Features

### User Management and Authentication
- Registration and login for users.
- Two user roles: **Regular Users** and **Admins**.
- Users can view their profile with scan history and credit usage.

### Credit System
- Each user receives **20 free scans per day** (reset at midnight).
- Admins manage credit requests, approving or denying them as needed.
- Each document scan deducts **one credit** from the user’s balance.

### Document Scanning & Matching
- Users upload plain text documents for scanning.
- System compares uploaded documents with existing ones using basic text similarity algorithms.
- **AI-powered document matching** (using OpenAI, Gemini, or DeepSeek) is an optional feature to improve accuracy.

### Smart Analytics Dashboard
- Tracks the number of scans per user daily.
- Identifies the most common document topics.
- Displays top users based on scans and credit usage.
- Admins can generate reports on credit usage.

---

## Technologies Used
- **Frontend**: HTML, CSS, JavaScript (No frameworks)
- **Backend**: Python (Flask) or Node.js (Express)
- **Database**: SQLite
- **Authentication**: Basic username-password login with hashed passwords
- **File Storage**: Local storage for uploaded documents
- **Text Matching Logic**: Custom algorithms like Levenshtein distance or word frequency matching
- **Optional AI Integration**: OpenAI, Gemini, or DeepSeek for advanced matching

---

## System Architecture
The project is built with the following architecture:

### Frontend:
- Simple user interface to register, log in, upload documents, and view profile.
- Display for credits, past scans, and requests for additional credits.

### Backend:
- Handles user registration, authentication, credit management, document upload, and text matching.
- Admin functions to approve credit requests and generate analytics.

### Database:
- Stores user data, document data, and credit balance.
- SQLite is used for simplicity, though a more robust database can be implemented as needed.

---

## API Endpoints

| Method  | Endpoint                   | Description                                      |
|---------|----------------------------|--------------------------------------------------|
| POST    | `/auth/register`            | User registration.                               |
| POST    | `/auth/login`               | User login (session-based).                     |
| GET     | `/user/profile`             | Get user profile (credits, past scans).         |
| POST    | `/scan/upload`              | Upload document for scanning (uses 1 credit).   |
| GET     | `/matches/<int:doc_id>`     | Get matching documents for the uploaded document. |
| POST    | `/user/request_credit`      | Request admin approval for additional credits.  |
| GET     | `/admin/dashboard`          | Admin dashboard with analytics.                 |

---

## Workflow

### 1. User Authentication
- Users register using a username and password, which are securely stored using hashed passwords.
- After registration, users can log in, and sessions are created for authorized access.

### 2. Credit System
- Each user starts with **20 free credits**, which are reset daily at midnight.
- If a user exceeds their daily limit, they must request additional credits.
- Admins have the ability to approve or deny these requests.
- Users can view their credit usage in their profile.

### 3. Document Scanning & Matching
- Users can upload plain text documents.
- Each document scan costs **1 credit**.
- The system compares the uploaded document against the existing documents using a basic text matching algorithm (such as Levenshtein distance).
- **Optional**: AI-powered matching using advanced technologies like OpenAI or Gemini can improve document comparison accuracy.

### 4. Admin Analytics
- Admins have access to an analytics dashboard, where they can:
  - View the total number of scans performed by users.
  - Identify the most common document types scanned.
  - Monitor the users with the highest credit usage.
  - Generate credit usage reports.

---

## Detailed Implementation

### Backend (Flask)

#### Database Setup:
- SQLite is used for storing user data, documents, and credit balances. The database includes two main tables: `users` and `documents`.

#### User Registration & Login:
- Users can register with a username and password, which is hashed before being stored.
- A session is created upon successful login.

#### Document Upload & Scanning:
- Users upload documents as plain text files.
- The document is stored locally, and its content is compared to existing documents in the database using a simple text similarity algorithm.

#### Credit Management:
- Each document scan deducts **one credit** from the user’s account.
- Users can request additional credits, which an admin can approve or deny.

#### Text Matching:
- A basic text matching algorithm compares the content of uploaded documents with those already in the system.

---

## Set Up the Project on Your System

### Prerequisites
Ensure you have the following installed:

- **Python 3.7+**  
  [Download Python](https://www.python.org/downloads/)

---

### Setup Instructions

1. **Clone the Repository**  
   Clone the repository to your local machine:

   ```bash
   git clone https://github.com/BARDAVAL-JAGADEESH/Document-Scanner-System.git
   cd Document-Scanner-System


13# Run the Application
Start the Flask application by running:
in bash after changing director to   Document-Scanner-System run below command 

python app.py


Access the Application

Open your browser and go to http://127.0.0.1:5000.

Register as a user or admin, and start using the system.

Future Enhancements
AI-Powered Matching: Integrate OpenAI, Gemini, or DeepSeek for more accurate document matching.

File Type Support: Add support for more file types (e.g., DOCX, XLSX).

Cloud Storage: Use cloud storage (e.g., AWS S3) for document storage instead of local storage.

Advanced Analytics: Add more detailed analytics, such as user activity trends and document similarity heatmaps.




