// Debug log to confirm script is loaded
console.log('main.js loaded successfully');

// Make the function globally available
window.sendMessage = async function() {
    console.log('sendMessage function called');
    const inputBox = document.querySelector("textarea");
    const sendButton = document.getElementById('sendButton');
    const chatContainer = document.querySelector("main");
    let message = inputBox.value.trim();
    
    if (!message) return;

    // Disable send button and show loading state
    if (sendButton) {
        sendButton.disabled = true;
        sendButton.innerHTML = '<span class="material-symbols-outlined text-2xl">hourglass_empty</span>';
    }
    
    const originalPlaceholder = inputBox.placeholder;
    inputBox.placeholder = "Sending message...";
    inputBox.value = "";
    inputBox.disabled = true;

    try {
        // Add user message to chat
        if (chatContainer) {
            const userMessage = document.createElement('div');
            userMessage.className = 'flex justify-end mb-4';
            userMessage.innerHTML = `
                <div class="bg-primary text-white rounded-lg p-3 max-w-[70%]">
                    <p>${message}</p>
                </div>
            `;
            chatContainer.appendChild(userMessage);
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }

        const response = await fetch("/chat", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({message})
        });

        const data = await response.json();
        console.log("Response from server:", data);

        if (!response.ok) {
            throw new Error(data.error || `HTTP error! status: ${response.status}`);
        }
        
        // Add bot response to chat
        if (chatContainer) {
            const botMessage = document.createElement('div');
            botMessage.className = 'flex mb-4';
            botMessage.innerHTML = `
                <div class="bg-gray-100 rounded-lg p-3 max-w-[70%]">
                    <p>${data.response}</p>
                </div>
            `;
            chatContainer.appendChild(botMessage);
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }
        
    } catch (error) {
        console.error("Error sending message:", error);
        
        // Show error in chat
        if (chatContainer) {
            const errorMessage = document.createElement('div');
            errorMessage.className = 'flex justify-center mb-4';
            errorMessage.innerHTML = `
                <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
                    <p>Error: ${error.message || 'Failed to send message'}</p>
                </div>
            `;
            chatContainer.appendChild(errorMessage);
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }
        
        // Restore the message that failed to send
        inputBox.value = message;
    } finally {
        // Re-enable the input and button
        inputBox.disabled = false;
        inputBox.placeholder = originalPlaceholder;
        inputBox.focus();
        
        if (sendButton) {
            sendButton.disabled = false;
            sendButton.innerHTML = '<span class="material-symbols-outlined text-2xl">send</span>';
        }
    }
}

// Debug function to check if elements exist
function checkElements() {
    console.log('Checking elements...');
    const sendButton = document.getElementById('sendButton');
    const textarea = document.querySelector('textarea');
    console.log('Send button exists:', !!sendButton);
    console.log('Textarea exists:', !!textarea);
    return { sendButton, textarea };
}

// Add event listeners when the DOM is fully loaded
console.log('Adding DOMContentLoaded event listener');
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM fully loaded');
    const { sendButton, textarea } = checkElements();
    // Add click event to the send button
    if (sendButton) {
        console.log('Adding click event to send button');
        sendButton.addEventListener('click', function(e) {
            console.log('Send button clicked');
            e.preventDefault();
            window.sendMessage();
        });
    }
    
    // Add Enter key press event to the textarea
    if (textarea) {
        console.log('Adding keypress event to textarea');
        textarea.addEventListener('keypress', function(e) {
            console.log('Key pressed in textarea:', e.key);
            if (e.key === 'Enter' && !e.shiftKey) {
                console.log('Enter key pressed without shift');
                e.preventDefault();
                window.sendMessage();
            }
        });
    }
});
