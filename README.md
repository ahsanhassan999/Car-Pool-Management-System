# Car Pool Management System

This is a Flask-based web application for managing a carpool service. It provides separate interfaces for three types of users: Admins, Drivers, and Riders.

## Features

### General Features
- **User Authentication:** Secure user registration and login system.
- **User Roles:** Distinct roles for Admin, Driver, and Rider, each with specific permissions.
- **Profile Management:** Users can view and update their profile information.

### Admin Features
- **Admin Dashboard:** A central place for administrators to manage the platform.
- **User Management:** Admins can create, view, edit, and delete users.
- **Car Management:** Admins can view and manage all cars in the system.

### Driver Features
- **Driver Dashboard:** A personalized dashboard for drivers.
- **Vehicle Management:** Drivers can register and manage their own vehicles.
- **Ride Management:**
    - Create new rides with details like start/end points, departure time, and price.
    - View their active rides and the riders who have booked a seat.
    - Manage booking requests from riders (accept or reject).
    - End a ride after its completion.

### Rider Features
- **Rider Dashboard:** A personalized dashboard for riders.
- **Browse Rides:** Riders can view all available active rides.
- **Book a Ride:** Riders can request to book a seat on a ride.
- **Ride Status:** View the status of their current booked ride.
- **Booking History:** View a history of their past bookings.

## Technical Details
- **Backend:** Flask (Python)
- **Database:** MySQL
- **Frontend:** HTML, CSS, JavaScript

## Running the Application
1.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
2.  **Set up the database:**
    - Create a MySQL database named `Car-Pool-Management-System`.
    - Import the `schema_updates.sql` file to set up the tables.
3.  **Run the application:**
    ```bash
    python main.py## Web Routes

### Public Routes
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Home page |
| `GET` | `/about` | About page |
| `GET` | `/login` | Login page |
| `POST` | `/login` | Handles user login |
| `GET` | `/signup` | Sign up page |
| `POST` | `/signup` | Handles user registration |
| `GET` | `/logout` | Logs out the current user |

### Driver Routes
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/driver-dashboard` | Driver's main dashboard |
| `GET` | `/driver/create-ride` | Form to create a new ride |
| `POST` | `/driver/create-ride` | Handles new ride creation |
| `GET` | `/driver/my-ride` | View driver's active ride and manage requests |
| `POST` | `/driver/manage-request/<int:booking_id>/<action>` | Accept or reject a booking request |
| `POST` | `/driver/end-ride/<int:ride_id>` | Ends and archives a ride |

### Rider Routes
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/rider-dashboard` | Rider's main dashboard |
| `GET` | `/rider/all-rides` | Browse all available active rides |
| `POST` | `/rider/request-ride/<int:ride_id>` | Request to join a ride |
| `GET` | `/rider/my-ride` | View rider's current confirmed ride |

### Admin Routes
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/admin-dashboard` | Admin's main dashboard |
| `GET` | `/admin-dashboard/all-users` | View and manage all users |
| `POST` | `/admin-dashboard/edit-user` | Edit user details |
| `POST` | `/admin-dashboard/delete-user` | Delete a user |
| `POST` | `/admin-dashboard/add-user` | Add a new user |
| `GET` | `/admin-dashboard/all-cars` | View and
    ```
The application will be available at `http://127.0.0.1:3000`.