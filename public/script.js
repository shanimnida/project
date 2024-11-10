function showError(messageId, message) {
    const messageElement = document.getElementById(messageId);
    messageElement.textContent = message;
    messageElement.style.display = "block";
}

function hideError(messageId) {
    const messageElement = document.getElementById(messageId);
    messageElement.textContent = "";
    messageElement.style.display = "none";
}

function isValidEmailFormat(email) {
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailPattern.test(email);
}

function validateEmail(email, messageId) {
    hideError(messageId);
    if (!isValidEmailFormat(email)) {
        showError(messageId, "Please enter a valid email address.");
        return false;
    }
    return true;
}

function verifyPassword(newPassword, confirmPassword, messageId) {
    hideError(messageId);
    if (newPassword !== confirmPassword) {
        showError(messageId, "Passwords do not match.");
        return false;
    }
    if (newPassword.length < 8) {
        showError(messageId, "Password must be at least 8 characters long.");
        return false;
    }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(newPassword)) {
        showError(messageId, "Password must contain at least one special character.");
        return false;
    }
    if (!/[0-9]/.test(newPassword)) {
        showError(messageId, "Password must contain at least one number.");
        return false;
    }
    return true;
}

function checkPasswordStrength(password) {
    const passwordStrength = document.getElementById("password_strength");
    let strength = 0;
    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) strength++;

    if (strength === 0 || strength === 1) {
        passwordStrength.textContent = "Weak";
        passwordStrength.style.color = "red";
    } else if (strength === 2) {
        passwordStrength.textContent = "Medium";
        passwordStrength.style.color = "orange";
    } else {
        passwordStrength.textContent = "Strong";
        passwordStrength.style.color = "green";
    }
}

function togglePassword(inputId) {
    const passwordInput = document.getElementById(inputId); 
    const newInputType = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', newInputType);
}

function submitSignUp(event) {
    event.preventDefault();
    
    const fullName = document.getElementById('full_name').value;
    const mobileNumber = document.getElementById('mob_number').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('pass1').value;
    const confirmPassword = document.getElementById('pass2').value;

    // Validate email and password
    if (!validateEmail(email, 'signup_error_message') || !verifyPassword(password, confirmPassword, 'verify_message')) {
        return; // Return early if validation fails
    }

    const payload = {
        full_name: fullName,
        mob_number: mobileNumber,
        email: email,
        password: password,
    };

    let hasProcessed = false; // Flag to ensure only one alert

    fetch('/signup', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
    })
    .then(response => {
        return response.json(); // Ensure we get the JSON body of the response
    })
    .then(data => {
        // If already processed, do not show alerts again
        if (hasProcessed) return;
        hasProcessed = true;

        console.log('Response:', data); // Log the full response for debugging

        if (data.success) {
            alert('Account created successfully! Redirecting...');
            window.location.href = 'login.html';
        } else {
            alert(data.message); // Show error message from the server
        }
    })
    .catch(error => {
        // If already processed, do not show alerts again
        if (hasProcessed) return;
        hasProcessed = true;

        console.error('Error during signup:', error);
        alert('An error occurred. Please try again.');
    });
}




function submitLogin(event) {
    event.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    if (!validateEmail(email, 'login_error_message')) {
        return;
    }

    const payload = {
        email: email,
        password: password,
    };

    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Login successful! Redirecting...');
            window.location.href = 'dashboard.html';
        } else {
            showError('login_error_message', data.message);
        }
    })
    .catch(error => {
        console.error('Error during login:', error);
        showError('login_error_message', 'An error occurred. Please try again.');
    });
}

async function submitResetPassword(event) {
    event.preventDefault();

    const resetKey = document.getElementById('reset-token').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    if (newPassword !== confirmPassword) {
        document.getElementById('verify_message').textContent = "Passwords do not match.";
        document.getElementById('verify_message').style.display = 'block';
        return;
    }

    try {
        const response = await fetch('/reset-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ resetKey, newPassword })
        });

        const result = await response.json();

        if (response.ok) {
            alert(result.message);
            window.location.href = 'login.html';
        } else {
            document.getElementById('token_message').textContent = result.message;
            document.getElementById('token_message').style.display = 'block';
        }
    } catch (error) {
        console.error('Error:', error);
        document.getElementById('token_message').textContent = "An error occurred. Please try again.";
        document.getElementById('token_message').style.display = 'block';
    }
}

