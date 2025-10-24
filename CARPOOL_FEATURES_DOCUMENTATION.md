# Car Pool Management System - Ride & Booking Features

## Overview
This document describes the newly implemented ride and booking management features for the Car Pool Management System (CPMS).

## Schema Updates Required

Before using these features, run the SQL commands in `schema_updates.sql`:

```sql
-- 1. Add is_active field to rides table
ALTER TABLE rides 
ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE AFTER driver_notes;

-- 2. Update bookings table to support additional statuses
ALTER TABLE bookings 
MODIFY COLUMN booking_status ENUM('Pending','Confirmed','Cancelled','Completed','Rejected') NOT NULL DEFAULT 'Pending';
```

## System Constraints

1. **One Active Ride Per Driver**: A driver can only have ONE active ride at any time
2. **Seat Management**: Available seats are only decremented when a driver ACCEPTS a booking request
3. **Booking States**: 
   - `Pending` - Rider has requested to join (seats NOT yet reserved)
   - `Confirmed` - Driver has accepted (seats ARE reserved)
   - `Rejected` - Driver has declined the request
   - `Completed` - Ride has ended successfully
   - `Cancelled` - Booking was cancelled

## Implemented Functions

### 1. `create_new_ride(driver_id, car_id, start, end, dep_time, price, notes)`

**Purpose**: Allows a driver to create a new ride

**Checks**:
- Ensures driver doesn't have an existing active ride
- Verifies the car belongs to the driver
- Automatically sets `total_seats = car_seats - 1` (reserves 1 seat for driver)

**Returns**: `(success: bool, message: str, ride_id: int or None)`

**Usage**:
```python
success, message, ride_id = create_new_ride(
    driver_id=1004,
    car_id=101,
    start="Johar Block 17",
    end="Defence Phase 8",
    dep_time=datetime(2025, 10, 25, 9, 0),
    price=250.00,
    notes="No smoking please"
)
```

---

### 2. `get_all_active_rides()`

**Purpose**: Retrieves all active rides with available seats for riders to browse

**Returns**: `(success: bool, message: str, rides_list: list of dicts or None)`

**Includes**:
- Ride details (route, time, price, seats)
- Driver information (name, phone)
- Car details (make, model, license plate)

---

### 3. `request_to_join_ride(rider_id, ride_id)`

**Purpose**: Allows a rider to request a seat on a ride

**Checks**:
- Available seats > 0
- Rider doesn't already have a Pending or Confirmed booking for this ride
- Rider is not the driver of the ride

**Important**: Creates booking with `status='Pending'` - does NOT decrement available_seats yet

**Returns**: `(success: bool, message: str, booking_id: int or None)`

---

### 4. `driver_manage_request(booking_id, action, driver_id)`

**Purpose**: Allows driver to accept or reject a pending booking request

**Parameters**:
- `action`: Either 'Accept' or 'Reject'
- `driver_id`: For verification that the driver owns this ride

**If Accept**:
1. Updates booking status to 'Confirmed'
2. **CRITICAL**: Decrements `rides.available_seats` by 1

**If Reject**:
1. Updates booking status to 'Rejected'
2. Seats remain available

**Returns**: `(success: bool, message: str)`

---

### 5. `get_driver_active_ride_details(driver_id)`

**Purpose**: Gets driver's active ride with all pending and confirmed bookings

**Returns**: `(success: bool, message: str, data: dict or None)`

**Data Structure**:
```python
{
    'ride': {...},  # Ride details
    'confirmed_riders': [...],  # List of confirmed riders
    'pending_requests': [...]   # List of pending requests
}
```

---

### 6. `get_rider_current_ride(rider_id)`

**Purpose**: Gets rider's current confirmed ride with driver and car details

**Returns**: `(success: bool, message: str, ride_data: dict or None)`

**Includes**:
- Complete ride information
- Driver contact details
- Car information

---

### 7. `end_ride_and_archive(ride_id, driver_id)`

**Purpose**: Completes a ride and moves it to history

**Actions**:
1. Archives ride to `ridehistory` table
2. Updates all Confirmed bookings to 'Completed'
3. Updates all Pending bookings to 'Cancelled'
4. Deletes the ride from active rides table

**Returns**: `(success: bool, message: str)`

---

## Flask Routes

### Driver Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/driver/create-ride` | GET, POST | Form to create a new ride |
| `/driver/my-ride` | GET | View active ride and manage bookings |
| `/driver/manage-request/<booking_id>/<action>` | POST | Accept/Reject booking requests |
| `/driver/end-ride/<ride_id>` | POST | Complete and archive a ride |

### Rider Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/rider/all-rides` | GET | Browse all available rides |
| `/rider/request-ride/<ride_id>` | POST | Request to join a ride |
| `/rider/my-ride` | GET | View current confirmed ride |

## Workflow Examples

### Driver Workflow

1. **Create Ride**
   - Navigate to `/driver/create-ride`
   - Select car, enter route, time, and price
   - Submit form
   - System checks for existing active ride
   - Ride is created with `is_active=TRUE`

2. **Manage Bookings**
   - Navigate to `/driver/my-ride`
   - View pending requests
   - Click "Accept" or "Reject" for each request
   - When accepting, seat count automatically decrements

3. **End Ride**
   - Navigate to `/driver/my-ride`
   - Click "End Ride" button
   - Confirm action
   - Ride is archived to history
   - All bookings updated accordingly

### Rider Workflow

1. **Browse Rides**
   - Navigate to `/rider/all-rides`
   - View all available rides
   - Check route, time, price, and available seats

2. **Request Ride**
   - Click "Request to Join" on desired ride
   - Booking created with `status='Pending'`
   - Wait for driver approval

3. **View Confirmed Ride**
   - Navigate to `/rider/my-ride`
   - See complete ride details
   - View driver contact information
   - Note departure time and location

## Database Schema Reference

### rides Table (Updated)
```sql
- ride_id (PK)
- driver_id (FK -> users)
- car_id (FK -> cars)
- starting_point
- destination_point
- departure_time
- total_seats
- available_seats
- price_per_seat
- driver_notes
- created_at
- is_active (NEW)
```

### bookings Table (Updated)
```sql
- booking_id (PK)
- ride_id (FK -> rides)
- rider_id (FK -> users)
- booking_status (ENUM: Pending, Confirmed, Cancelled, Completed, Rejected)
- seats_booked
- booked_at
```

### ridehistory Table
```sql
- history_id (PK)
- original_ride_id
- driver_id
- starting_point
- destination_point
- departure_time
- final_price
- total_riders
- completion_date
```

## Important Notes

### Pricing Note
The current implementation uses the existing `price_per_seat` field from the schema. If you need separate `min_price_per_person` and `max_price_per_person` fields as mentioned in requirements, uncomment and run the alternative SQL in `schema_updates.sql`.

### Security Features
- All routes have role-based access control
- Drivers can only manage their own rides
- Riders cannot book their own rides
- CSRF protection on all forms (if implemented)

### Error Handling
All functions return a tuple with:
- `success` (bool): Whether operation succeeded
- `message` (str): User-friendly error/success message
- `data` (optional): Result data (ride_id, booking_id, etc.)

## Testing Checklist

- [ ] Driver can create a ride
- [ ] Driver cannot create multiple active rides
- [ ] Riders can see all active rides
- [ ] Rider can request to join a ride
- [ ] Rider cannot request the same ride twice
- [ ] Driver can accept/reject requests
- [ ] Accepting a request decrements available_seats
- [ ] Rejecting a request keeps seats available
- [ ] Driver can view all pending and confirmed riders
- [ ] Rider can view their confirmed ride details
- [ ] Driver can end a ride
- [ ] Ended rides are properly archived
- [ ] Bookings are updated correctly when ride ends

## Future Enhancements

1. Real-time notifications for booking status changes
2. Ride rating and review system
3. Payment integration
4. GPS-based location tracking
5. Chat system between drivers and riders
6. Recurring ride schedules
7. Price negotiation feature
8. Multi-seat booking support
9. Cancellation policies and refunds
10. Admin dashboard for ride monitoring

## Troubleshooting

### "Database connection failed"
- Check MySQL service is running
- Verify database credentials in `get_db_connection()`

### "You already have an active ride"
- Driver must end or cancel current ride before creating a new one
- Check `rides` table for rides with `is_active=TRUE`

### "No seats available"
- All seats are booked (confirmed)
- Check `available_seats` column in rides table

### "Booking not found"
- Verify booking_id exists
- Check if booking was deleted

## Support

For issues or questions:
1. Check this documentation
2. Review function docstrings in `main.py`
3. Check Flask application logs for error messages
4. Verify database schema matches requirements
