# App/views.py
from django.shortcuts import render, redirect
from .forms import CustomUserCreationForm, CustomAuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout
from bcrypt import hashpw, gensalt
from .forms import ReclamationForm
from .models import Reclamation
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.contrib.auth.decorators import user_passes_test


def home(request):
    return render(request, 'home.html')

def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            raw_password = form.cleaned_data['password1']

            # Hash the password using bcrypt
            hashed_password = hashpw(raw_password.encode('utf-8'), gensalt())

            # Save the user with the hashed password
            user = form.save(commit=False)
            user.password = hashed_password.decode('utf-8')
            user.save()

            # Log in the user
            login(request, user)
            
            return redirect('home')  # Change 'home' to the name of your home page
    else:
        form = CustomUserCreationForm()
    return render(request, 'register.html', {'form': form})

def user_login(request):
    if request.method == 'POST':
        form = CustomAuthenticationForm(request, request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('home')  # Change 'home' to the name of your home page
    else:
        form = CustomAuthenticationForm()
    return render(request, 'login.html', {'form': form})

def user_logout(request):
    logout(request)
    return redirect('home')  # Change 'home' to the name of your home page



@login_required
def submit_reclamation(request):
    if request.method == 'POST':
        form = ReclamationForm(request.POST)
        if form.is_valid():
            reclamation = form.save(commit=False)
            user_public_key = serialization.load_pem_public_key(
                request.user.encryption_key.encode(),
                backend=default_backend()
            )
            # Perform decryption here if needed

            # Save the reclamation
            reclamation.user = request.user
            reclamation.save()
            return redirect('home')  # Change 'home' to the name of your home page
    else:
        form = ReclamationForm()
    return render(request, 'submit_reclamation.html', {'form': form})


@user_passes_test(lambda u: u.is_superuser, login_url='home')
def view_reclamations(request):
    reclamations = Reclamation.objects.all()
    decrypted_reclamations = []

    for reclamation in reclamations:
        user_private_key = serialization.load_pem_private_key(
            request.user.encryption_key.encode(),
            password=None,
            backend=default_backend()
        )
        
        # Decrypt the message
        cipher = Cipher(algorithms.AES(user_private_key), modes.CFB(reclamation.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(reclamation.encrypted_message) + decryptor.finalize()

        decrypted_reclamations.append({
            'user': reclamation.user,
            'decrypted_message': decrypted_message.decode('utf-8'),
            'date_created': reclamation.date_created,
        })

    return render(request, 'view_reclamations.html', {'decrypted_reclamations': decrypted_reclamations})