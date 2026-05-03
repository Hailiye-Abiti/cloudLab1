<?php
// =======================================================
// PHP Error Reporting (for debugging purposes)
ini_set('display_errors', 1);
error_reporting(E_ALL);
// =======================================================

// Include database configuration and helper functions
// ASSUMPTION: 'config.php' includes $conn, generate_otp(), AND starts the session with session_start()
include 'config.php'; 

$response = ['success' => false, 'message' => ''];

// Utility function to check if a user is logged in
function is_logged_in() {
    // Check if user_id exists in session and is numeric/valid
    return isset($_SESSION['user_id']) && is_numeric($_SESSION['user_id']);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $action = $_POST['action'] ?? '';

    // --- Logout Action ---
    if ($action == 'logout') {
        session_destroy();
        $_SESSION = array(); 
        $response['success'] = true;
        $response['message'] = 'You have been logged out.';
        $response['redirect'] = 'login.html';
    }
    
    // ===========================================================
    // --- UC-01: Register Account ---
    // ===========================================================
    elseif ($action == 'register') {
        $student_id = $conn->real_escape_string($_POST['student_id'] ?? '');
        $full_name = $conn->real_escape_string($_POST['full_name'] ?? '');
        $department = $conn->real_escape_string($_POST['department'] ?? 'N/A'); 
        $email = $conn->real_escape_string($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $user_role = 'Student';

        $check_sql = "SELECT user_id FROM users WHERE student_id = ? OR email = ?";
        $stmt = $conn->prepare($check_sql);
        $stmt->bind_param("ss", $student_id, $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $response['message'] = 'Account already exists with this Student ID or Email.';
        } else {
            if (strlen($password) < 8) {
                $response['message'] = 'Password must be at least 8 characters long.';
            } else {
                $password_hash = password_hash($password, PASSWORD_DEFAULT);
                $otp = generate_otp(); 
                
                $insert_sql = "INSERT INTO users (student_id, full_name, department, email, password_hash, user_role, is_verified, otp_code) 
                               VALUES (?, ?, ?, ?, ?, ?, 0, ?)";
                $stmt_insert = $conn->prepare($insert_sql);
                $stmt_insert->bind_param("sssssss", $student_id, $full_name, $department, $email, $password_hash, $user_role, $otp);

                if ($stmt_insert->execute()) {
                    $response['success'] = true;
                    $response['message'] = 'Registration successful! Check your email for OTP: ' . $otp . '. You will be redirected to the verification page.';
                    $response['redirect'] = 'verify.html'; 
                } else {
                    $response['message'] = 'Registration failed due to a system error: ' . $conn->error;
                }
                $stmt_insert->close();
            }
        }
        $stmt->close();
    }

    // ===========================================================
    // --- UC-02: Login (FIXED: Added full_name to response) ---
    // ===========================================================
    elseif ($action == 'login') {
        $username = $conn->real_escape_string($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        $sql = "SELECT user_id, password_hash, user_role, full_name, is_verified FROM users WHERE student_id = ? OR email = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ss", $username, $username);
        $stmt->execute();
        $stmt->store_result();
        
        if ($stmt->num_rows == 1) {
            $stmt->bind_result($user_id, $password_hash, $user_role, $full_name, $is_verified);
            $stmt->fetch();

            if (!password_verify($password, $password_hash)) {
                $response['message'] = 'Incorrect username or password.';
            } elseif ($is_verified == 0) {
                $response['message'] = 'Your account is not verified. Please verify to continue.';
                $response['redirect'] = 'verify.html';
            } else {
                $_SESSION['user_id'] = $user_id;
                $_SESSION['user_role'] = $user_role;
                $_SESSION['full_name'] = $full_name;
                
                $response['success'] = true;
                $response['message'] = 'Login successful!';
                $response['full_name'] = $full_name; // IMPORTANT: Return full name to client for sessionStorage
                
                $redirect_url = match ($user_role) {
                    'Admin' => 'admin_dashboard.html', // Redirect Admin here
                    'HOD' => 'hod_dashboard.html', 
                    'Instructor' => 'instructor_dashboard.html', 
                    default => 'student_dashboard.html', 
                };
                $response['redirect'] = $redirect_url;
            }
        } else {
            $response['message'] = 'Incorrect username or password.';
        }
        $stmt->close();
    }
    
    // ===========================================================
    // --- UC-01/UC-03: OTP Verification ---
    // ===========================================================
    elseif ($action == 'verify_otp') {
        $email = $conn->real_escape_string($_POST['email'] ?? ''); 
        $otp_input = $_POST['otp'] ?? '';

        $sql = "SELECT user_id, otp_code FROM users WHERE email = ? AND is_verified = 0";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        
        if ($stmt->num_rows == 1) {
            $stmt->bind_result($user_id, $stored_otp);
            $stmt->fetch();

            if ($otp_input === $stored_otp) {
                $update_sql = "UPDATE users SET is_verified = 1, otp_code = NULL WHERE user_id = ?";
                $stmt_update = $conn->prepare($update_sql);
                $stmt_update->bind_param("i", $user_id);
                $stmt_update->execute();

                $response['success'] = true;
                $response['message'] = 'Account verified successfully! You can now log in.';
                $response['redirect'] = 'login.html';
            } else {
                $response['message'] = 'Invalid OTP. Please check and try again.';
            }
            $stmt->close();
        } else {
            $response['message'] = 'Verification failed. Account not found or already verified.';
        }
    }
    
    // ===========================================================
    // --- UC-03: Password Reset - Step 1 (Send OTP) ---
    // ===========================================================
    elseif ($action == 'send_reset_otp') {
        $username = $conn->real_escape_string($_POST['username'] ?? '');

        $sql = "SELECT user_id, email FROM users WHERE student_id = ? OR email = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ss", $username, $username);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows == 1) {
            $stmt->bind_result($user_id, $email);
            $stmt->fetch();
            $otp = generate_otp();

            $reset_sql = "INSERT INTO password_resets (email, otp_code, expires_at) VALUES (?, ?, NOW() + INTERVAL 10 MINUTE) ON DUPLICATE KEY UPDATE otp_code=?, expires_at=NOW() + INTERVAL 10 MINUTE";
            $stmt_reset = $conn->prepare($reset_sql);
            $stmt_reset->bind_param("sss", $email, $otp, $otp);
            $stmt_reset->execute();
            
            $response['success'] = true;
            $response['message'] = 'OTP sent to registered email/phone. OTP: ' . $otp . '. You will be redirected.';
            $response['email'] = $email;
            $response['redirect'] = 'new_password.html'; 
        } else {
            $response['message'] = 'No account found with this information.';
        }
        $stmt->close();
    }

    // ===========================================================
    // --- UC-03: Password Reset - Step 2 (Set New Password) ---
    // ===========================================================
    elseif ($action == 'set_new_password') {
        $email = $conn->real_escape_string($_POST['email'] ?? '');
        $otp_input = $_POST['otp'] ?? '';
        $new_password = $_POST['new_password'] ?? '';

        $sql = "SELECT email FROM password_resets WHERE email = ? AND otp_code = ? AND expires_at > NOW()";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ss", $email, $otp_input);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows == 1) {
            if (strlen($new_password) < 8) {
                $response['message'] = 'New password must be at least 8 characters long.';
            } else {
                $password_hash = password_hash($new_password, PASSWORD_DEFAULT);
                $update_sql = "UPDATE users SET password_hash = ? WHERE email = ?";
                $stmt_update = $conn->prepare($update_sql);
                $stmt_update->bind_param("ss", $password_hash, $email);

                if ($stmt_update->execute()) {
                    $delete_sql = "DELETE FROM password_resets WHERE email = ?";
                    $stmt_delete = $conn->prepare($delete_sql);
                    $stmt_delete->bind_param("s", $email);
                    $stmt_delete->execute();
                    
                    $response['success'] = true;
                    $response['message'] = 'Password reset successful! Redirecting to login.';
                    $response['redirect'] = 'login.html'; 
                } else {
                    $response['message'] = 'System error: Unable to update password.';
                }
                $stmt_update->close();
            }
        } else {
            $response['message'] = 'Invalid or expired OTP. Please try the reset process again.';
        }
        $stmt->close();
    }
    
    // ===========================================================
    // --- UC-04: Get Feedback Categories Action (Student/Staff) ---
    // ===========================================================
    elseif ($action == 'get_feedback_categories') {
        if (!is_logged_in()) {
            $response['message'] = 'Unauthorized access. Please log in.';
            $response['redirect'] = 'login.html';
        } else {
            // Fetches ONLY ACTIVE categories for student/general view
            $sql = "SELECT category_id, category_name FROM feedback_categories WHERE is_active = TRUE ORDER BY category_name";
            $result = $conn->query($sql);
            
            if ($result) {
                $categories = [];
                while ($row = $result->fetch_assoc()) {
                    $categories[] = $row;
                }
                $response['success'] = true;
                $response['categories'] = $categories;
            } else {
                $response['message'] = 'Database error while fetching categories: ' . $conn->error;
            }
        }
    }
    
    // ===========================================================
    // --- UC-05: Submit Feedback Action (Student) ---
    // ===========================================================
    elseif ($action == 'submit_feedback') {
        if (!is_logged_in()) {
            $response['message'] = 'Session expired. Please log in again.';
            $response['redirect'] = 'login.html';
        } else {
            $user_id = $_SESSION['user_id'];
            
            $category_id = (int)($_POST['category_id'] ?? 0);
            $target_name = $conn->real_escape_string($_POST['target_name'] ?? '');
            $rating_q1 = (int)($_POST['rating_q1'] ?? 0);
            $rating_q2 = (int)($_POST['rating_q2'] ?? 0);
            $rating_q3 = (int)($_POST['rating_q3'] ?? 0);
            $overall_comment = $conn->real_escape_string($_POST['overall_comment'] ?? '');

            // Check if required fields are present
            if ($category_id === 0 || empty($target_name)) {
                $response['message'] = 'Invalid submission data.';
            } else {
                $insert_sql = "INSERT INTO feedback_submissions (user_id, category_id, target_name, rating_q1, rating_q2, rating_q3, overall_comment) 
                               VALUES (?, ?, ?, ?, ?, ?, ?)";
                
                $stmt_insert = $conn->prepare($insert_sql);
                
                if ($stmt_insert) {
                    $stmt_insert->bind_param("iisiiss", 
                        $user_id, $category_id, $target_name, $rating_q1, $rating_q2, $rating_q3, $overall_comment
                    );

                    if ($stmt_insert->execute()) {
                        $response['success'] = true;
                        $response['message'] = 'Feedback submitted successfully! Thank you.';
                    } else {
                        $response['message'] = 'Submission failed: ' . $stmt_insert->error;
                    }
                    $stmt_insert->close();
                } else {
                    $response['message'] = 'Submission failed (Prepare error): ' . $conn->error;
                }
            }
        }
    }
    
    // ===========================================================
    // --- UC-07: Change Password Action (All Users) ---
    // ===========================================================
    elseif ($action == 'change_password') {
        if (!is_logged_in()) {
            $response['message'] = 'Session expired. Please log in.';
            $response['redirect'] = 'login.html';
        } else {
            $user_id = $_SESSION['user_id'];
            $current_password = $_POST['current_password'] ?? '';
            $new_password = $_POST['new_password'] ?? '';

            $sql = "SELECT password_hash FROM users WHERE user_id = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $stmt->store_result();
            
            if ($stmt->num_rows == 1) {
                $stmt->bind_result($stored_hash);
                $stmt->fetch();
                $stmt->close();
                
                if (!password_verify($current_password, $stored_hash)) {
                    $response['message'] = 'Incorrect current password.';
                } elseif (strlen($new_password) < 8) {
                    $response['message'] = 'New password must be at least 8 characters long.';
                } else {
                    $new_password_hash = password_hash($new_password, PASSWORD_DEFAULT);
                    $update_sql = "UPDATE users SET password_hash = ? WHERE user_id = ?";
                    $stmt_update = $conn->prepare($update_sql);
                    $stmt_update->bind_param("si", $new_password_hash, $user_id);

                    if ($stmt_update->execute()) {
                        $response['success'] = true;
                        $response['message'] = 'Password changed successfully! You are being logged out for security.';
                        
                        // Security Step: Destroy session immediately
                        session_destroy(); 
                        $_SESSION = array();
                    } else {
                        $response['message'] = 'System error: Unable to update password.';
                    }
                    $stmt_update->close();
                }
            } else {
                $response['message'] = 'User not found in the system.';
            }
        }
    }

    // ===========================================================
    // --- UC-09: Get Student's Feedback Submission History ---
    // ===========================================================
    elseif ($action == 'get_student_history') {
        if (!is_logged_in() || $_SESSION['user_role'] !== 'Student') {
            $response['message'] = 'Access Denied. You must be a logged-in student.';
            $response['redirect'] = 'login.html';
        } else {
            $user_id = $_SESSION['user_id'];
            
            $sql = "SELECT 
                        fs.target_name, 
                        fc.category_name, 
                        ROUND( (fs.rating_q1 + fs.rating_q2 + fs.rating_q3) / 3, 1) AS overall_rating,
                        fs.overall_comment, 
                        fs.submission_date 
                    FROM feedback_submissions fs
                    JOIN feedback_categories fc ON fs.category_id = fc.category_id
                    WHERE fs.user_id = ?
                    ORDER BY fs.submission_date DESC";
            
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result) {
                $history = [];
                while ($row = $result->fetch_assoc()) {
                    $history[] = $row;
                }
                $response['success'] = true;
                $response['history'] = $history;
            } else {
                $response['message'] = 'Database error while fetching history: ' . $conn->error;
            }
            $stmt->close();
        }
    }
    
    // ===========================================================
    // --- UC-10: Get User Profile Details ---
    // ===========================================================
    elseif ($action == 'get_profile_details') {
        if (!is_logged_in()) {
            $response['message'] = 'Session expired. Please log in.';
            $response['redirect'] = 'login.html';
        } else {
            $user_id = $_SESSION['user_id'];
            
            $sql = "SELECT student_id, full_name, department, email FROM users WHERE user_id = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result && $result->num_rows === 1) {
                $profile = $result->fetch_assoc();
                $response['success'] = true;
                $response['profile'] = $profile;
            } else {
                $response['message'] = 'User profile not found.';
            }
            $stmt->close();
        }
    }

    // ===========================================================
    // --- UC-10: Update User Profile ---
    // ===========================================================
    elseif ($action == 'update_profile') {
        if (!is_logged_in()) {
            $response['message'] = 'Session expired. Please log in.';
            $response['redirect'] = 'login.html';
        } else {
            $user_id = $_SESSION['user_id'];
            
            $full_name = $conn->real_escape_string($_POST['full_name'] ?? '');
            $department = $conn->real_escape_string($_POST['department'] ?? '');
            $email = $conn->real_escape_string($_POST['email'] ?? '');

            if (empty($full_name) || empty($department) || empty($email)) {
                 $response['message'] = 'All fields are required.';
            } else {
                // Check if the new email is already used by another user (excluding the current user)
                $check_email_sql = "SELECT user_id FROM users WHERE email = ? AND user_id != ?";
                $stmt_check = $conn->prepare($check_email_sql);
                $stmt_check->bind_param("si", $email, $user_id);
                $stmt_check->execute();
                $stmt_check->store_result();

                if ($stmt_check->num_rows > 0) {
                    $response['message'] = 'This email is already taken by another account.';
                } else {
                    $update_sql = "UPDATE users SET full_name = ?, department = ?, email = ? WHERE user_id = ?";
                    $stmt = $conn->prepare($update_sql);
                    $stmt->bind_param("sssi", $full_name, $department, $email, $user_id);
                    
                    if ($stmt->execute()) {
                        // Update the session variable for the full name immediately
                        $_SESSION['full_name'] = $full_name; 
                        
                        $response['success'] = true;
                        $response['message'] = 'Profile updated successfully!';
                    } else {
                        $response['message'] = 'Failed to update profile: ' . $conn->error;
                    }
                    $stmt->close();
                }
                $stmt_check->close();
            }
        }
    }
    
    // ===========================================================
    // --- UC-11: Admin - Get All Users ---
    // ===========================================================
    elseif ($action == 'get_all_users') {
        // Only Admin can view all users
        if (!is_logged_in() || $_SESSION['user_role'] !== 'Admin') {
            $response['message'] = 'Access Denied. Only Administrators can view this page.';
            $response['redirect'] = 'login.html';
        } else {
            $sql = "SELECT user_id, full_name, student_id, email, department, user_role, is_verified FROM users ORDER BY user_role, full_name";
            $result = $conn->query($sql);
            
            if ($result) {
                $users = [];
                while ($row = $result->fetch_assoc()) {
                    $users[] = $row;
                }
                $response['success'] = true;
                $response['users'] = $users;
            } else {
                $response['message'] = 'Database error while fetching users: ' . $conn->error;
            }
        }
    }
    
    // ===========================================================
    // --- UC-11: Admin - Get Single User (for editing) ---
    // ===========================================================
    elseif ($action == 'get_single_user') {
        if (!is_logged_in() || $_SESSION['user_role'] !== 'Admin') {
            $response['message'] = 'Access Denied.';
            $response['redirect'] = 'login.html';
        } else {
            $user_id = (int)($_POST['user_id'] ?? 0);
            $sql = "SELECT user_id, full_name, student_id, email, department, user_role FROM users WHERE user_id = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result && $result->num_rows === 1) {
                $response['success'] = true;
                $response['user'] = $result->fetch_assoc();
            } else {
                $response['message'] = 'User not found.';
            }
            $stmt->close();
        }
    }

    // ===========================================================
    // --- UC-11: Admin - Add New User ---
    // ===========================================================
    elseif ($action == 'add_user') {
        if (!is_logged_in() || $_SESSION['user_role'] !== 'Admin') {
            $response['message'] = 'Access Denied.';
            $response['redirect'] = 'login.html';
        } else {
            $student_id = $conn->real_escape_string($_POST['student_id'] ?? NULL);
            $full_name = $conn->real_escape_string($_POST['full_name'] ?? '');
            $department = $conn->real_escape_string($_POST['department'] ?? '');
            $email = $conn->real_escape_string($_POST['email'] ?? '');
            $user_role = $conn->real_escape_string($_POST['user_role'] ?? 'Student');
            $password = $_POST['password'] ?? '';
            
            if (empty($full_name) || empty($email) || empty($department) || empty($password)) {
                $response['message'] = 'Full Name, Email, Department, and Password are required.';
            } elseif (strlen($password) < 8) {
                $response['message'] = 'Password must be at least 8 characters long.';
            } else {
                // Check if email or student_id already exists
                $check_sql = "SELECT user_id FROM users WHERE email = ?";
                $check_params = [$email];
                $check_types = "s";
                
                if (!empty($student_id)) {
                    $check_sql .= " OR student_id = ?";
                    $check_params[] = $student_id;
                    $check_types .= "s";
                }
                
                $stmt_check = $conn->prepare($check_sql);
                $stmt_check->bind_param($check_types, ...$check_params);
                $stmt_check->execute();
                $stmt_check->store_result();

                if ($stmt_check->num_rows > 0) {
                    $response['message'] = 'Account already exists with this Email or Student ID.';
                    $stmt_check->close();
                } else {
                    $password_hash = password_hash($password, PASSWORD_DEFAULT);
                    $insert_sql = "INSERT INTO users (student_id, full_name, department, email, password_hash, user_role, is_verified) 
                                   VALUES (?, ?, ?, ?, ?, ?, 1)";
                    $stmt_insert = $conn->prepare($insert_sql);
                    
                    $stmt_insert->bind_param("ssssss", $student_id, $full_name, $department, $email, $password_hash, $user_role);

                    if ($stmt_insert->execute()) {
                        $response['success'] = true;
                        $response['message'] = "User {$full_name} ({$user_role}) created successfully.";
                    } else {
                        $response['message'] = 'Failed to create user: ' . $conn->error;
                    }
                    $stmt_insert->close();
                }
            }
        }
    }
    
    // ===========================================================
    // --- UC-11: Admin - Update Existing User ---
    // ===========================================================
    elseif ($action == 'update_user') {
        if (!is_logged_in() || $_SESSION['user_role'] !== 'Admin') {
            $response['message'] = 'Access Denied.';
            $response['redirect'] = 'login.html';
        } else {
            $user_id = (int)($_POST['user_id'] ?? 0);
            $student_id = $conn->real_escape_string($_POST['student_id'] ?? NULL);
            $full_name = $conn->real_escape_string($_POST['full_name'] ?? '');
            $department = $conn->real_escape_string($_POST['department'] ?? '');
            $email = $conn->real_escape_string($_POST['email'] ?? '');
            $user_role = $conn->real_escape_string($_POST['user_role'] ?? 'Student');
            $password = $_POST['password'] ?? '';
            
            if (empty($user_id) || empty($full_name) || empty($email) || empty($department)) {
                $response['message'] = 'Missing required fields.';
            } else {
                // 1. Check for email/student_id conflict (excluding current user)
                $check_sql = "SELECT user_id FROM users WHERE (email = ? AND user_id != ?)";
                $check_params = [$email, $user_id];
                $check_types = "si";
                
                if (!empty($student_id)) {
                    $check_sql .= " OR (student_id = ? AND user_id != ?)";
                    $check_params[] = $student_id;
                    $check_params[] = $user_id;
                    $check_types .= "si";
                }
                
                $stmt_check = $conn->prepare($check_sql);
                $stmt_check->bind_param($check_types, ...$check_params);
                $stmt_check->execute();
                $stmt_check->store_result();
                
                if ($stmt_check->num_rows > 0) {
                    $response['message'] = 'The updated Email or Student ID is already used by another account.';
                    $stmt_check->close();
                } else {
                    $update_sql = "UPDATE users SET student_id = ?, full_name = ?, department = ?, email = ?, user_role = ?";
                    $update_params = [$student_id, $full_name, $department, $email, $user_role];
                    $update_types = "sssss";
                    
                    // 2. Handle optional password update
                    if (!empty($password)) {
                        if (strlen($password) < 8) {
                            $response['message'] = 'New password must be at least 8 characters long.';
                            goto end_update_user; 
                        }
                        $password_hash = password_hash($password, PASSWORD_DEFAULT);
                        $update_sql .= ", password_hash = ?";
                        $update_params[] = $password_hash;
                        $update_types .= "s";
                    }
                    
                    $update_sql .= " WHERE user_id = ?";
                    $update_params[] = $user_id;
                    $update_types .= "i";
                    
                    $stmt_update = $conn->prepare($update_sql);
                    $stmt_update->bind_param($update_types, ...$update_params);

                    if ($stmt_update->execute()) {
                        $response['success'] = true;
                        $response['message'] = "User account for {$full_name} updated successfully.";
                    } else {
                        $response['message'] = 'Failed to update user: ' . $conn->error;
                    }
                    $stmt_update->close();
                }
            }
        }
        end_update_user: // Label for goto, used for clean error exit
    }
    
    // ===========================================================
    // --- UC-11: Admin - Delete User ---
    // ===========================================================
    elseif ($action == 'delete_user') {
        if (!is_logged_in() || $_SESSION['user_role'] !== 'Admin') {
            $response['message'] = 'Access Denied.';
            $response['redirect'] = 'login.html';
        } else {
            $user_id = (int)($_POST['user_id'] ?? 0);
            
            // SECURITY: Prevent deleting the currently logged-in Admin!
            if ($user_id === $_SESSION['user_id']) {
                $response['message'] = 'You cannot delete your own active administrator account.';
            } else {
                // Start a transaction to ensure data integrity
                $conn->begin_transaction();
                try {
                    // Delete related feedback submissions first
                    $delete_submissions_sql = "DELETE FROM feedback_submissions WHERE user_id = ?";
                    $stmt_submissions = $conn->prepare($delete_submissions_sql);
                    $stmt_submissions->bind_param("i", $user_id);
                    $stmt_submissions->execute();
                    $stmt_submissions->close();

                    // Delete the user
                    $delete_user_sql = "DELETE FROM users WHERE user_id = ?";
                    $stmt = $conn->prepare($delete_user_sql);
                    $stmt->bind_param("i", $user_id);

                    if ($stmt->execute()) {
                        $conn->commit();
                        $response['success'] = true;
                        $response['message'] = 'User and all related data deleted successfully.';
                    } else {
                        throw new Exception('Failed to delete user.');
                    }
                    $stmt->close();
                } catch (Exception $e) {
                    $conn->rollback();
                    $response['message'] = 'Failed to delete user: ' . $conn->error;
                }
            }
        }
    }
}
// -------------------- End of POST actions --------------------

$conn->close();
// Set the header to indicate JSON response
header('Content-Type: application/json');
echo json_encode($response);
?>