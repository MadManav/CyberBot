// Quiz state
let quizState = {
    currentQuestion: 0,
    score: 0,
    questions: [],
    userAnswers: [],
    quizStarted: false
};

// DOM Elements
const quizContainer = document.getElementById('quizContainer');
const quizContent = document.getElementById('quizContent');
const currentQuestionEl = document.getElementById('currentQuestion');
const totalQuestionsEl = document.getElementById('totalQuestions');
const scoreEl = document.getElementById('score');
const progressBar = document.getElementById('progressBar');
const prevBtn = document.getElementById('prevBtn');
const nextBtn = document.getElementById('nextBtn');

// Initialize the quiz
async function initializeQuiz() {
    try {
        // Load base questions
        const response = await fetch('/static/questions.json');
        const data = await response.json();
        quizState.questions = data.questions;
        
        // Initialize UI
        totalQuestionsEl.textContent = quizState.questions.length;
        updateProgress();
        
        // Show first question
        displayQuestion();
        
        // Add event listeners
        nextBtn.addEventListener('click', nextQuestion);
        prevBtn.addEventListener('click', prevQuestion);
        
    } catch (error) {
        console.error('Error initializing quiz:', error);
        quizContent.innerHTML = `
            <div class="bg-red-50 border-l-4 border-red-500 p-4 mb-4">
                <div class="flex">
                    <div class="text-red-500">
                        <svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>
                        </svg>
                    </div>
                    <div class="ml-3">
                        <p class="text-sm text-red-700">Failed to load quiz questions. Please try again later.</p>
                    </div>
                </div>
            </div>
        `;
    }
}

// Display current question
function displayQuestion() {
    const currentQ = quizState.questions[quizState.currentQuestion];
    if (!currentQ) return;
    
    const optionsHtml = currentQ.options.map((option, index) => `
        <div class="option p-4 my-2 border rounded-lg cursor-pointer hover:bg-gray-50 transition-colors" 
             data-index="${index}">
            ${String.fromCharCode(65 + index)}. ${option}
        </div>
    `).join('');
    
    quizContent.innerHTML = `
        <div class="question-card bg-white p-6 rounded-lg shadow-sm border border-gray-200">
            <h3 class="text-lg font-medium text-gray-900 mb-4">${currentQ.question}</h3>
            <div class="options space-y-2">
                ${optionsHtml}
            </div>
            <div id="explanation" class="mt-4 p-4 bg-blue-50 rounded-lg hidden">
                <p class="text-sm text-blue-700">${currentQ.explanation}</p>
            </div>
        </div>
    `;
    
    // Add event listeners to options
    document.querySelectorAll('.option').forEach(option => {
        option.addEventListener('click', () => selectAnswer(parseInt(option.dataset.index)));
    });
    
    // Update navigation buttons
    updateNavigation();
}

// Handle answer selection
function selectAnswer(selectedIndex) {
    const currentQ = quizState.questions[quizState.currentQuestion];
    const options = document.querySelectorAll('.option');
    const explanation = document.getElementById('explanation');
    
    // Disable all options
    options.forEach(opt => {
        opt.style.pointerEvents = 'none';
    });
    
    // Mark correct and incorrect answers
    options.forEach((opt, index) => {
        if (index === currentQ.correctIndex) {
            opt.classList.add('bg-green-50', 'border-green-500');
        } else if (index === selectedIndex && selectedIndex !== currentQ.correctIndex) {
            opt.classList.add('bg-red-50', 'border-red-500');
        }
    });
    
    // Update score if correct
    if (selectedIndex === currentQ.correctIndex) {
        quizState.score++;
        scoreEl.textContent = quizState.score;
    }
    
    // Store user answer
    quizState.userAnswers[quizState.currentQuestion] = selectedIndex;
    
    // Show explanation
    if (explanation) {
        explanation.classList.remove('hidden');
    }
    
    // Enable next button
    nextBtn.disabled = false;
}

// Update navigation buttons
function updateNavigation() {
    prevBtn.disabled = quizState.currentQuestion === 0;
    nextBtn.textContent = quizState.currentQuestion === quizState.questions.length - 1 ? 'Finish' : 'Next';
    nextBtn.disabled = quizState.userAnswers[quizState.currentQuestion] === undefined;
}

// Update progress bar
function updateProgress() {
    const progress = ((quizState.currentQuestion + 1) / quizState.questions.length) * 100;
    progressBar.style.width = `${progress}%`;
    currentQuestionEl.textContent = quizState.currentQuestion + 1;
}

// Go to next question
function nextQuestion() {
    if (quizState.currentQuestion < quizState.questions.length - 1) {
        quizState.currentQuestion++;
        displayQuestion();
        updateProgress();
    } else {
        showResults();
    }
}

// Go to previous question
function prevQuestion() {
    if (quizState.currentQuestion > 0) {
        quizState.currentQuestion--;
        displayQuestion();
        updateProgress();
    }
}

// Show quiz results
function showResults() {
    const scorePercentage = Math.round((quizState.score / quizState.questions.length) * 100);
    
    let message = '';
    if (scorePercentage >= 80) {
        message = 'Excellent! You have a strong understanding of cybersecurity.';
    } else if (scorePercentage >= 60) {
        message = 'Good job! You have a decent understanding of cybersecurity.';
    } else {
        message = 'Keep learning! Review the questions and try again.';
    }
    
    quizContent.innerHTML = `
        <div class="text-center py-8">
            <div class="mx-auto w-24 h-24 bg-green-100 rounded-full flex items-center justify-center mb-4">
                <span class="text-3xl font-bold text-green-600">${scorePercentage}%</span>
            </div>
            <h3 class="text-2xl font-bold text-gray-900 mb-2">${message}</h3>
            <p class="text-gray-600 mb-6">You scored ${quizState.score} out of ${quizState.questions.length} questions correctly.</p>
            <div class="flex justify-center space-x-4">
                <button id="retryBtn" class="px-6 py-2 bg-blue-100 text-blue-700 rounded-lg hover:bg-blue-200 transition-colors">
                    Try Again
                </button>
                <button id="reviewBtn" class="px-6 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors">
                    Review Answers
                </button>
            </div>
        </div>
    `;
    
    // Add event listeners for result actions
    document.getElementById('retryBtn').addEventListener('click', resetQuiz);
    document.getElementById('reviewBtn').addEventListener('click', reviewAnswers);
}

// Reset the quiz
function resetQuiz() {
    quizState = {
        currentQuestion: 0,
        score: 0,
        questions: quizState.questions,
        userAnswers: [],
        quizStarted: false
    };
    
    scoreEl.textContent = '0';
    initializeQuiz();
}

// Review answers
function reviewAnswers() {
    let reviewHtml = '<div class="space-y-6">';
    
    quizState.questions.forEach((question, index) => {
        const userAnswer = quizState.userAnswers[index];
        const isCorrect = userAnswer === question.correctIndex;
        
        reviewHtml += `
            <div class="p-4 border rounded-lg ${isCorrect ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'}">
                <div class="flex justify-between items-start">
                    <h4 class="font-medium">Question ${index + 1}: ${question.question}</h4>
                    <span class="px-2 py-1 text-xs rounded-full ${isCorrect ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}">
                        ${isCorrect ? 'Correct' : 'Incorrect'}
                    </span>
                </div>
                <div class="mt-2">
                    <p class="text-sm ${isCorrect ? 'text-green-700' : 'text-red-700'}">
                        <span class="font-medium">Your answer:</span> ${question.options[userAnswer]}
                    </p>
                    ${!isCorrect ? `
                        <p class="text-sm text-green-700 mt-1">
                            <span class="font-medium">Correct answer:</span> ${question.options[question.correctIndex]}
                        </p>
                    ` : ''}
                    <p class="text-sm text-gray-600 mt-2">${question.explanation}</p>
                </div>
            </div>
        `;
    });
    
    reviewHtml += '</div>';
    
    quizContent.innerHTML = `
        <div>
            <h3 class="text-xl font-bold mb-4">Review Your Answers</h3>
            ${reviewHtml}
            <div class="mt-6 text-center">
                <button id="backToResults" class="px-6 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors">
                    Back to Results
                </button>
            </div>
        </div>
    `;
    
    document.getElementById('backToResults').addEventListener('click', showResults);
}

// Initialize the quiz when the page loads
document.addEventListener('DOMContentLoaded', () => {
    // Check if we're on the quiz page
    if (window.location.hash === '#quiz') {
        document.getElementById('chatContainer').classList.add('hidden');
        quizContainer.classList.remove('hidden');
        initializeQuiz();
    }
});
