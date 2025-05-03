// Function to switch forms (if needed on the same page)
function switchForm(formId) {
    document.querySelectorAll('.form').forEach(f => f.classList.remove('active'));
    document.getElementById(formId).classList.add('active');
  }
  
  // Function to toggle password visibility
  function togglePassword(inputId) {
    const passwordInput = document.getElementById(inputId);
    const eyeIcon = passwordInput.nextElementSibling;
    if (passwordInput.type === "password") {
        passwordInput.type = "text";
        eyeIcon.classList.remove('fa-eye-slash');
        eyeIcon.classList.add('fa-eye');
    } else {
        passwordInput.type = "password";
        eyeIcon.classList.remove('fa-eye');
        eyeIcon.classList.add('fa-eye-slash');
    }
  }
  
  // Add input validation for password field (used in signup and reset password forms)
  function validatePassword() {
    const passwordInput = document.querySelector('input[name="password"]');
    const confirmPasswordInput = document.querySelector('input[name="confirm_password"]');
    if (passwordInput && confirmPasswordInput) {
        if (passwordInput.value !== confirmPasswordInput.value) {
            confirmPasswordInput.setCustomValidity("Passwords do not match");
        } else {
            confirmPasswordInput.setCustomValidity("");
        }
    }
  }
  
  // Attach validation to forms
  document.addEventListener('DOMContentLoaded', () => {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        const passwordInput = form.querySelector('input[name="password"]');
        const confirmPasswordInput = form.querySelector('input[name="confirm_password"]');
        if (passwordInput && confirmPasswordInput) {
            passwordInput.addEventListener('input', validatePassword);
            confirmPasswordInput.addEventListener('input', validatePassword);
        }
    });
  });