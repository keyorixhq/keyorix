// Simple Keyorix Dashboard App
console.log('Keyorix Dashboard loaded successfully');

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard initialized');
    
    // Load system status
    fetch('/health')
        .then(response => response.json())
        .then(data => {
            console.log('System status:', data);
        })
        .catch(error => {
            console.error('Failed to load system status:', error);
        });
});
