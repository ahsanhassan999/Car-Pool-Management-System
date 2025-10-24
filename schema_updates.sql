-- Schema updates for Car Pool Management System
-- Run these SQL commands in your MySQL database to update the schema

-- 1. Add is_active field to rides table
ALTER TABLE rides 
ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE AFTER driver_notes;

-- 2. Update rides table to support min/max pricing (keep price_per_seat for now, or rename it)
-- Option A: Keep existing price_per_seat and treat it as the final price
-- Option B: Add separate min/max fields (commented out below if needed)
-- ALTER TABLE rides 
-- ADD COLUMN min_price_per_person DECIMAL(10,2) AFTER available_seats,
-- ADD COLUMN max_price_per_person DECIMAL(10,2) AFTER min_price_per_person;
-- ALTER TABLE rides DROP COLUMN price_per_seat; -- if using min/max instead

-- 3. Update bookings table to support additional statuses
ALTER TABLE bookings 
MODIFY COLUMN booking_status ENUM('Pending','Confirmed','Cancelled','Completed','Rejected') NOT NULL DEFAULT 'Pending';

-- 4. Verify the changes
-- DESCRIBE rides;
-- DESCRIBE bookings;
