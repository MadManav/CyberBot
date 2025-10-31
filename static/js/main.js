// Debug log to confirm script is loaded
console.log('main.js loaded successfully');

// Utility to escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Create analysis card with ML scores
function createAnalysisCard(analysis) {
    const riskLevel = analysis.is_suspicious ? 'High' : 'Low';
    const riskColor = analysis.is_suspicious ? 'text-red-500' : 'text-green-500';
    const confidencePercent = (analysis.confidence * 100).toFixed(1);
    const mlPercent = (analysis.ml_score * 100).toFixed(1);
    
    const riskIcon = analysis.is_suspicious ? 'warning' : 'shield_check';
    const riskStatus = analysis.is_suspicious ? 'Phishing Risk' : 'Safe';
    
    const keywordsHtml = analysis.keywords && analysis.keywords.length > 0 
        ? analysis.keywords.map(k => `<span class="inline-block bg-red-50 text-red-700 px-2 py-1 rounded text-xs font-medium">${escapeHtml(k)}</span>`).join('')
        : '<span class="text-gray-500 text-sm">None detected</span>';

    return `
        <div class="border border-gray-300 rounded-lg overflow-hidden bg-white">
            <div class="grid grid-cols-[30%_1fr] items-center gap-x-6 border-b border-gray-200 px-4 py-3">
                <p class="text-sm font-medium text-gray-600">Status</p>
                <div class="flex items-center gap-2">
                    <span class="material-symbols-outlined ${riskColor}">${riskIcon}</span>
                    <p class="text-sm font-semibold ${riskColor}">${riskStatus}</p>
                </div>
            </div>
            
            <div class="grid grid-cols-[30%_1fr] items-center gap-x-6 border-b border-gray-200 px-4 py-3">
                <p class="text-sm font-medium text-gray-600">Risk Level</p>
                <p class="text-sm font-semibold ${riskColor}">${riskLevel}</p>
            </div>
            
            <div class="grid grid-cols-[30%_1fr] items-center gap-x-6 border-b border-gray-200 px-4 py-3">
                <p class="text-sm font-medium text-gray-600">Confidence</p>
                <div class="flex items-center gap-2">
                    <div class="w-24 bg-gray-200 rounded-full h-2">
                        <div class="bg-blue-500 h-2 rounded-full" style="width: ${confidencePercent}%"></div>
                    </div>
                    <p class="text-sm font-semibold">${confidencePercent}%</p>
                </div>
            </div>
            
            <div class="grid grid-cols-[30%_1fr] items-center gap-x-6 border-b border-gray-200 px-4 py-3">
                <p class="text-sm font-medium text-gray-600">ML Score</p>
                <p class="text-sm font-semibold">${mlPercent}%</p>
            </div>
            
            ${analysis.url_domain ? `
            <div class="grid grid-cols-[30%_1fr] items-center gap-x-6 border-b border-gray-200 px-4 py-3">
                <p class="text-sm font-medium text-gray-600">Domain</p>
                <p class="text-sm font-mono break-all">${escapeHtml(analysis.url_domain)}</p>
            </div>
            ` : ''}
            
            <div class="grid grid-cols-[30%_1fr] gap-x-6 px-4 py-3">
                <p class="text-sm font-medium text-gray-600">Warning Signs</p>
                <div class="flex flex-wrap gap-2">${keywordsHtml}</div>
            </div>
        </div>
    `;
}

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
    inputBox.placeholder = "Analyzing message...";
    inputBox.value = "";
    inputBox.disabled = true;

    try {
        // Add user message to chat
        if (chatContainer) {
            const userMessage = document.createElement('div');
            userMessage.className = 'flex justify-end mb-4 gap-3';
            userMessage.innerHTML = `
                <div class="bg-blue-500 text-white rounded-lg p-3 max-w-[70%]">
                    <p>${escapeHtml(message)}</p>
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
        
        // Add bot response to chat with analysis
        if (chatContainer) {
            const botMessage = document.createElement('div');
            botMessage.className = 'flex mb-4 gap-3';
            
            const analysis = data.analysis || {};
            const botResponse = data.response || 'Unable to generate response';
            const analysisCard = createAnalysisCard(analysis);
            
            botMessage.innerHTML = `
                <div class="bg-gray-100 rounded-lg p-4 max-w-2xl flex-1">
                    <p class="text-gray-800 mb-4">${escapeHtml(botResponse)}</p>
                    ${analysisCard}
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
                    <p>❌ Error: ${error.message || 'Failed to send message'}</p>
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