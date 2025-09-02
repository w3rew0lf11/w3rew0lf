/**
 * MOBILE NAVIGATION TOGGLE
 * Handles showing/hiding mobile menu and active link states
 */

// DOM Elements
const menuIcon = document.querySelector('#menu-icon');
const navbar = document.querySelector('.navbar');
const navLinks = document.querySelectorAll('header nav a');
const header = document.querySelector('header');

/**
 * Toggle mobile menu when hamburger icon is clicked
 */
const toggleMobileMenu = () => {
    menuIcon.classList.toggle('bx-x');
    navbar.classList.toggle('active');
};

/**
 * Close mobile menu when a nav link is clicked
 */
const closeMobileMenu = () => {
    menuIcon.classList.remove('bx-x');
    navbar.classList.remove('active');
};

/**
 * Set active state for clicked nav link
 * @param {HTMLElement} clickedLink - The nav link that was clicked
 */
const setActiveLink = (clickedLink) => {
    // Remove active class from all links
    navLinks.forEach(link => link.classList.remove('active'));
    // Add active class to clicked link
    clickedLink.classList.add('active');
};

/**
 * Handle scroll events for sticky header
 */
const handleScroll = () => {
    // Add/remove sticky class based on scroll position
    header.classList.toggle('sticky', window.scrollY > 100);
};

// Event Listeners
menuIcon.addEventListener('click', toggleMobileMenu);

// Add click events to all nav links
navLinks.forEach(link => {
    link.addEventListener('click', () => {
        closeMobileMenu();
        setActiveLink(link);
    });
});

// Window scroll event
window.addEventListener('scroll', handleScroll);