-- Car Pool Management System - Full Schema & Seed Data
-- Execute this script to recreate the database schema (and seed data) on any machine.
-- WARNING: This script DROPS the existing database named `car-pool-management-system`.

SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';
SET time_zone = '+00:00';

DROP DATABASE IF EXISTS `car-pool-management-system`;
CREATE DATABASE IF NOT EXISTS `car-pool-management-system`
  DEFAULT CHARACTER SET utf8mb4
  COLLATE utf8mb4_general_ci;
USE `car-pool-management-system`;

-- --------------------------------------------------------
-- Table structure for `users`
-- --------------------------------------------------------

CREATE TABLE `users` (
  `user_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('Rider','Driver','Admin','') NOT NULL,
  `phone_number` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

INSERT INTO `users` (`user_id`, `name`, `email`, `password`, `role`, `phone_number`) VALUES
(1001, 'Syed Ahsan Hassan Rizvi', 's.ahsanhassanrizvi2004@gmail.com', 'pbkdf2:sha256:600000$hxxEYhr8vrnlrAWQ$3c3eabc4bbe8101e15c427b348c86297ebb18a5e7361592497ae1697e6889c0c', 'Admin', '03171155104'),
(1002, 'Ahsan Hassan', 'ahsanhassan@gmail.com', 'pbkdf2:sha256:600000$0KcLusLmsuQasVHi$0cc050c85f96383aa27fb8bcc239cb08ef8aabdc731bfdd7603e67415d1852a5', 'Admin', '03242695131'),
(1003, 'admin', 'admin@gmail.com', 'pbkdf2:sha256:600000$esxRkqbvVBUWNPp6$9ae0c9a4d117121d876768efb2ef7bf0a57e8cc04038e9f101fc8d085eb4bf8a', 'Admin', '***********'),
(1004, 'Hassan Rizvi', 'hassanrizvi@gmail.com', 'pbkdf2:sha256:600000$JgHFinrl7IMV4sgz$1a8af920d928511294bb905b9847f353c801f67ffedae7f01e207fc68ffbb211', 'Driver', '03171155105'),
(1005, 'Syed Farzam Ahmed Warsi', 'farzam@gmail.com', 'pbkdf2:sha256:600000$vm0uhDjKIEMDgRSN$9d73b3b93a01c5d409defcaced8849a7609ebd6c01b484b126deea9ef1ae2f5c', 'Admin', '00000000000'),
(1006, 'Syed Wasif Ali Rizvi', 'wasif@gmail.com', 'pbkdf2:sha256:600000$MDaeV2MkBnVHuqpi$b354504f1913ea27f83d3d7db150f523b43eca54989f4198cfdb6f681f907295', 'Rider', '9876543210'),
(1007, 'Shahrukh Khan', 'shahrukh@gmail.com', 'pbkdf2:sha256:600000$TTYG8xDA9Uy0dTBd$2d4df356512f0fa966b7fd85594d199c42682c8f2dae9f31fc0a9d91828f109c', 'Driver', '111111111111'),
(1008, 'Hassan Irshad', 'hassan@gmail.com', 'pbkdf2:sha256:600000$MaWfWsPgPZoaVMaD$e2008816f498f21b504f9616db9af2510a378d8f508a86c959402ef872a3492c', 'Rider', '2222222222'),
(1009, 'Ali Shayan', 'ali@gmail.com', 'pbkdf2:sha256:600000$cyWPtdx8t8kAtCdR$e17760ab77d13fa084b423012f1a96150b78b26d19840c229747c4bf3f5fe901', 'Rider', '3333333333'),
(1010, 'Hamza', 'hamza@gmail.com', 'pbkdf2:sha256:600000$ohC38vFvJv0xaDOv$c79be4b25eefd428ed42373065edee6cee942f16cda421d20f87d0e948783fae', 'Rider', '4444444444'),
(1014, 'Behroz', 'behroz@gmail.com', 'pbkdf2:sha256:600000$6fqiNCjSFBc1QIrJ$fa98e8f855f3a1167596827c92418646dc33715109efc63995b755e31604f277', 'Driver', '5555555555'),
(1015, 'Murtaza Rizvi', 'hmurtaza510@gmail.com', 'pbkdf2:sha256:600000$3CP0ehdBn0pTNYyu$075932b694efa196124c4f78eae20073ba523842d2971db8db8531b93fe7c8af', 'Rider', '03202726869');

-- --------------------------------------------------------
-- Table structure for `cars`
-- --------------------------------------------------------

CREATE TABLE `cars` (
  `car_id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `make` varchar(50) NOT NULL,
  `model` varchar(50) NOT NULL,
  `license_plate` varchar(20) NOT NULL,
  `seats` int(11) NOT NULL,
  PRIMARY KEY (`car_id`),
  UNIQUE KEY `license_plate` (`license_plate`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

INSERT INTO `cars` (`car_id`, `user_id`, `make`, `model`, `license_plate`, `seats`) VALUES
(101, 1007, 'Toyota', 'Corolla', 'AFQ-152', 4),
(102, 1004, 'Honda ', 'Civic', 'ABC-123', 4),
(103, 1015, 'Honda', 'City', 'BCD-999', 4);

-- --------------------------------------------------------
-- Table structure for `rides`
-- --------------------------------------------------------

CREATE TABLE `rides` (
  `ride_id` int(11) NOT NULL AUTO_INCREMENT,
  `driver_id` int(11) NOT NULL,
  `car_id` int(11) DEFAULT NULL,
  `starting_point` varchar(255) NOT NULL,
  `destination_point` varchar(255) NOT NULL,
  `departure_time` datetime NOT NULL,
  `total_seats` int(11) NOT NULL,
  `available_seats` int(11) NOT NULL,
  `min_price_per_person` decimal(10,2) DEFAULT NULL,
  `max_price_per_person` decimal(10,2) DEFAULT NULL,
  `price_per_seat` decimal(10,2) NOT NULL,
  `driver_notes` text DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`ride_id`),
  KEY `driver_id` (`driver_id`),
  KEY `car_id` (`car_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

INSERT INTO `rides` (`ride_id`, `driver_id`, `car_id`, `starting_point`, `destination_point`, `departure_time`, `total_seats`, `available_seats`, `min_price_per_person`, `max_price_per_person`, `price_per_seat`, `driver_notes`, `is_active`, `created_at`) VALUES
(15, 1007, 101, 'Johar, Block17', 'Defence, Phase 8', '2025-11-01 01:28:00', 3, 0, NULL, NULL, 500.00, 'ac', 0, '2025-10-31 20:28:29'),
(16, 1007, 101, 'Johar, Block17', 'Defence, Phase 8', '2025-11-01 01:31:00', 3, 0, NULL, NULL, 500.00, NULL, 0, '2025-10-31 20:31:22'),
(17, 1007, 101, 'Johar, Block17', 'Defence, Phase 8', '2025-11-01 01:55:00', 3, 0, NULL, NULL, 500.00, NULL, 0, '2025-10-31 20:55:30'),
(18, 1004, 102, 'Gulshan e Iqbal', 'Karachi University', '2025-12-03 01:57:00', 3, 0, NULL, NULL, 500.00, 'Acc', 0, '2025-10-31 20:57:39');

-- --------------------------------------------------------
-- Table structure for `bookings`
-- --------------------------------------------------------

CREATE TABLE `bookings` (
  `booking_id` int(11) NOT NULL AUTO_INCREMENT,
  `ride_id` int(11) NOT NULL,
  `rider_id` int(11) NOT NULL,
  `booking_status` enum('Pending','Confirmed','Cancelled','Completed','Rejected') NOT NULL DEFAULT 'Pending',
  `seats_booked` int(11) NOT NULL DEFAULT 1,
  `booked_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`booking_id`),
  UNIQUE KEY `ride_id` (`ride_id`,`rider_id`),
  KEY `rider_id` (`rider_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

INSERT INTO `bookings` (`booking_id`, `ride_id`, `rider_id`, `booking_status`, `seats_booked`, `booked_at`) VALUES
(17, 15, 1006, 'Completed', 1, '2025-10-31 20:28:39'),
(18, 16, 1006, 'Completed', 3, '2025-10-31 20:32:33'),
(19, 17, 1009, 'Completed', 3, '2025-10-31 20:59:22');

-- --------------------------------------------------------
-- Table structure for `ridehistory`
-- --------------------------------------------------------

CREATE TABLE `ridehistory` (
  `history_id` int(11) NOT NULL AUTO_INCREMENT,
  `original_ride_id` int(11) NOT NULL,
  `driver_id` int(11) NOT NULL,
  `starting_point` varchar(255) NOT NULL,
  `destination_point` varchar(255) NOT NULL,
  `departure_time` datetime NOT NULL,
  `final_price` decimal(10,2) NOT NULL,
  `total_riders` int(11) NOT NULL,
  `completion_date` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`history_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

INSERT INTO `ridehistory` (`history_id`, `original_ride_id`, `driver_id`, `starting_point`, `destination_point`, `departure_time`, `final_price`, `total_riders`, `completion_date`) VALUES
(1, 1, 1007, 'Johar, Block17', 'Defence, Phase 8', '2025-10-26 16:10:00', 500.00, 1, '2025-10-24 22:29:32'),
(2, 2, 1007, 'New karachi', 'Karachi University', '2025-10-26 07:30:00', 500.00, 1, '2025-10-25 10:30:47'),
(3, 3, 1007, 'New karachi', 'Karachi University', '2025-10-31 19:34:00', 500.00, 3, '2025-10-25 10:52:03'),
(4, 4, 1004, 'Johar block 17', 'Defence phase 2', '2025-10-25 16:00:00', 500.00, 0, '2025-10-25 10:56:49'),
(5, 5, 1007, 'Johar, Block 17', 'Defence, Phase 8', '2025-10-25 19:05:00', 500.00, 1, '2025-10-25 13:41:01'),
(6, 6, 1007, 'New karachi', 'Karachi University', '2025-10-30 20:45:00', 500.00, 1, '2025-10-25 14:51:56'),
(7, 9, 1007, 'New karachi', 'Karachi University', '2025-10-30 21:41:00', 500.00, 1, '2025-10-30 15:50:20'),
(8, 10, 1007, 'Johar, Block17', 'Defence, Phase 8', '2025-10-31 20:51:00', 500.00, 1, '2025-10-30 15:58:10'),
(9, 11, 1007, 'Johar, Block17', 'Defence, Phase 8', '2025-10-31 20:58:00', 500.00, 1, '2025-10-30 15:59:09'),
(10, 12, 1007, 'Johar, Block17', 'Defence, Phase 8', '2025-10-31 20:59:00', 500.00, 1, '2025-10-30 16:41:08'),
(11, 13, 1007, 'Johar, Block17', 'Defence, Phase 8', '2025-10-31 21:41:00', 500.00, 1, '2025-10-30 17:01:35'),
(12, 14, 1007, 'Johar, Block17', 'Defence, Phase 8', '2025-11-01 15:54:00', 500.00, 2, '2025-10-31 20:16:57'),
(13, 15, 1007, 'Johar, Block17', 'Defence, Phase 8', '2025-11-01 01:28:00', 500.00, 1, '2025-10-31 20:29:00'),
(14, 16, 1007, 'Johar, Block17', 'Defence, Phase 8', '2025-11-01 01:31:00', 500.00, 1, '2025-10-31 20:33:02'),
(15, 17, 1007, 'Johar, Block17', 'Defence, Phase 8', '2025-11-01 01:55:00', 500.00, 1, '2025-10-31 21:01:01'),
(16, 18, 1004, 'Gulshan e Iqbal', 'Karachi University', '2025-12-03 01:57:00', 500.00, 0, '2025-10-31 21:01:20');

-- --------------------------------------------------------
-- Foreign key constraints
-- --------------------------------------------------------

ALTER TABLE `cars`
  ADD CONSTRAINT `cars_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `rides`
  ADD CONSTRAINT `rides_ibfk_1` FOREIGN KEY (`driver_id`) REFERENCES `users` (`user_id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `rides_ibfk_2` FOREIGN KEY (`car_id`) REFERENCES `cars` (`car_id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `bookings`
  ADD CONSTRAINT `bookings_ibfk_1` FOREIGN KEY (`ride_id`) REFERENCES `rides` (`ride_id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `bookings_ibfk_2` FOREIGN KEY (`rider_id`) REFERENCES `users` (`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

COMMIT;
