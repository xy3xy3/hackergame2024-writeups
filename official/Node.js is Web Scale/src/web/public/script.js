// public/script.js

document.addEventListener('DOMContentLoaded', () => {
    const storeDisplay = document.getElementById('store-display');
    const refreshStoreBtn = document.getElementById('refresh-store');
    const setForm = document.getElementById('set-form');
    const setResponse = document.getElementById('set-response');
    const getForm = document.getElementById('get-form');
    const getResponse = document.getElementById('get-response');

    // Function to fetch and display the current store
    const fetchStore = async () => {
        try {
            const response = await fetch('/api/store');
            const data = await response.json();
            storeDisplay.textContent = JSON.stringify(data, null, 2);
        } catch (error) {
            storeDisplay.textContent = 'Error fetching store.';
            console.error('Error:', error);
        }
    };

    // Initial fetch
    fetchStore();

    // Refresh store on button click
    refreshStoreBtn.addEventListener('click', fetchStore);

    // Handle set form submission
    setForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const key = document.getElementById('key').value.trim();
        const value = document.getElementById('value').value.trim();

        if (!key || !value) {
            setResponse.textContent = 'Both key and value are required.';
            setResponse.style.color = 'red';
            return;
        }

        try {
            const res = await fetch('/set', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ key, value })
            });

            const result = await res.json();
            if (res.ok) {
                setResponse.textContent = result.message;
                setResponse.style.color = 'green';
                fetchStore(); // Refresh store after setting
                setForm.reset();
            } else {
                setResponse.textContent = result.message || 'Error setting key-value pair.';
                setResponse.style.color = 'red';
            }
        } catch (error) {
            setResponse.textContent = 'Error setting key-value pair.';
            setResponse.style.color = 'red';
            console.error('Error:', error);
        }
    });

    // Handle get form submission
    getForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const key = document.getElementById('get-key').value.trim();

        if (!key) {
            getResponse.textContent = 'Key is required.';
            getResponse.style.color = 'red';
            return;
        }

        try {
            const res = await fetch(`/get?key=${encodeURIComponent(key)}`, {
                method: 'GET',
                headers: {'Content-Type': 'application/json'},
            });

            const result = await res.json();
            if (res.ok) {
                getResponse.textContent = result.message;
                getResponse.style.color = 'green';
                getForm.reset();
            } else {
                getResponse.textContent = result.message || 'Error getting key-value pair.';
                getResponse.style.color = 'red';
            }
        } catch (error) {
            getResponse.textContent = 'Error getting key-value pair.';
            getResponse.style.color = 'red';
            console.error('Error:', error);
        }
    });
});
