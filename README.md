# CloudSync

CloudSync is a powerful and user-friendly desktop application that seamlessly integrates with Google Drive, allowing users to manage their cloud storage effortlessly. With features like file upload, download, delete, and wireless transfer, CloudSync provides a comprehensive solution for cloud file management.

## Table of Contents

- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
  - [Authentication](#authentication)
  - [Main Interface](#main-interface)
  - [File Operations](#file-operations)
  - [Wireless Transfer](#wireless-transfer)
- [Architecture](#architecture)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Features

- **Secure Authentication**: Utilizes Google's OAuth 2.0 for safe and secure user authentication.
- **File Management**: Upload, download, and delete files directly from your Google Drive.
- **Real-time File List**: View your Google Drive files with details like name, size, and modification date.
- **Wireless Transfer**: Easily transfer files from mobile devices using QR code technology.
- **User-friendly Interface**: Intuitive Windows Forms-based GUI for seamless interaction.
- **Persistent Authentication**: Remembers user sessions for convenience.

## Getting Started

### Prerequisites

- Windows operating system
- .NET Framework 4.7.2 or higher
- Internet connection
- Google account

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/Jamandalley/CloudSync.git
   ```
2. Open the solution in Visual Studio.
3. Restore NuGet packages.
4. Build the solution.
5. Run the application.

## Usage

### Authentication

1. Launch CloudSync.
2. Enter your Google account email address.
3. Click "Authenticate" to initiate the OAuth 2.0 flow.
4. Grant necessary permissions to CloudSync in the browser window that opens.

### Main Interface

After successful authentication, you'll be presented with the main interface, which includes:

- Welcome message with your email address
- File list view
- Operation buttons (Upload, Delete, Refresh, Open File, Wireless Transfer)
- Logout button

### File Operations

- **Upload**: Click "Upload" and select a file from your local machine to upload to Google Drive.
- **Delete**: Select a file in the list and click "Delete" to remove it from your Google Drive.
- **Refresh**: Click "Refresh" to update the file list with the latest changes.
- **Open File**: Double-click a file or select it and click "Open File" to view/edit it using the default application.

### Wireless Transfer

1. Click "Wireless Transfer" to generate a QR code.
2. Scan the QR code with your mobile device.
3. Open the provided URL in your mobile browser.
4. Select files on your mobile device to upload them directly to your Google Drive.

## Architecture

CloudSync follows a modular architecture with clear separation of concerns:

- **LandingPage**: Handles user authentication and acts as the entry point.
- **MainForm**: Provides the main user interface and file management operations.
- **QRCodeForm**: Generates and displays QR codes for wireless transfer.
- **GoogleAuthenticationService**: Manages Google OAuth 2.0 authentication process.
- **SQLiteUserRepository**: Handles local storage of user data using SQLite.

## Dependencies

- Google.Apis.Drive.v3: For interacting with Google Drive API
- System.Data.SQLite: For local database operations
- ZXing.Net: For QR code generation
- Dapper: For simplified database access

## Contributing

We welcome contributions to CloudSync! Please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them with descriptive commit messages.
4. Push your changes to your fork.
5. Submit a pull request to the main repository.

Please ensure your code adheres to the existing style conventions and includes appropriate tests.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Contact

For any queries or support, please contact the development team at **jamiuabimbade@gmail.com** or open an issue in the GitHub repository.

---

Thank you for using CloudSync! We hope this application enhances your cloud storage experience.
