 // Client-side validation for registration form
 import './styles.css';
function validateRegistration() {
    const name = document.getElementById('name').value.trim();
    const email = document.getElementById('email').value.trim();
    const contact = document.getElementById('contact').value.trim();
    const password = document.getElementById('password').value;
    
    if (name === '' || email === '' || contact === '' || password === '') {
      alert('All fields are required.');
      return false;
    }
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      alert('Please enter a valid email address.');
      return false;
    }
    
    // Additional validations for contact number or password strength can be added.
    return true;
  }
  
  // Client-side validation for login form
  function validateLogin() {
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    
    if (email === '' || password === '') {
      alert('Both email and password are required.');
      return false;
    }
    return true;
  }
  
