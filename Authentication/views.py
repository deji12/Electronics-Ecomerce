from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.mail import EmailMessage
from django.contrib.auth import login, logout
from .models import PasswordResetCode
from django.urls import reverse
from django.conf import settings
from django.utils import timezone
from Core.utils import (
    authenticate_user_with_email
)

def Register(request):

    # ensure user is not logged in
    if request.user.is_authenticated:
        return redirect('home')

    # check for incoming post requests
    if request.method == 'POST':

        # grab the data of the submitted form
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        # check to makke sure user filled all fields
        if not (username and email and password):
            messages.error(request, 'Please fill in all fields.')
            return redirect('register')
        
        # check if username and email already exist in the database
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return redirect('register')
        
        # check if email already exists in the database
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists.')
            return redirect('register')
        
        # check if password is at least 6 characters long
        if not len(password) >= 6:
            messages.error(request, 'Password must be at least 6 characters long.')
            return redirect('register')
        
        # create user if no error occurred
        user = User.objects.create_user(username=username, email=email, password=password)

        # login the user and redirect to home page
        login(request, user)
        return redirect('home')

    return render(request, 'Authentication/register.html')

def Login(request):

    # ensure user is not logged in
    if request.user.is_authenticated:
        return redirect('home')

    # check for incoming post requests
    if request.method == 'POST':

        # grab the data of the submitted for
        email = request.POST.get('email')
        password = request.POST.get('password')

        # make sure the email and password were entered
        if not (email and password):
            messages.error(request, 'Please enter your email and password.')
            return redirect('login')
        
        # authenticate the email and password
        user = authenticate_user_with_email(email, password)

        if user is not None:
            login(request, user)
            return redirect('home')

        else:
            messages.error(request, 'Invalid email or password.')
            return redirect('login')

    return render(request, 'Authentication/login.html')

def Logout(request):

    logout(request)
    return redirect('login')

def ForgotPassword(request):

    # ensure user is not logged in
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        
        # grab the data of the submitted for
        email = request.POST.get('email')

        # make sure the email was entered
        if not email:
            messages.error(request, 'Please enter your email.')
            return redirect('forgot-password')
        
        # check the database for a user with this email
        try:
            user = User.objects.get(email=email)

            # delete any existing reset codes for user
            PasswordResetCode.objects.filter(user=user).delete()

            # create a new password reset code for this user
            new_password_reset = PasswordResetCode(user=user)
            new_password_reset.save()
            
            # generate a unique reset URL for this user and email it to them
            reset_url_endpoint = reverse('reset-password', kwargs={'email': user.email, 'reset_code': new_password_reset.code})
            full_password_reset_url = f'{request.scheme}://{request.get_host()}{reset_url_endpoint}'

            # the email body
            email_body = f'Reset your password using the link provided below:\n\n\n{full_password_reset_url}'
        
            # sending password reset email 
            email_message = EmailMessage(
                'Reset your password', # email subject
                email_body,
                settings.EMAIL_HOST_USER, # email sender
                [email] # email  receiver 
            )

            email_message.fail_silently = True
            email_message.send()

            # redirect back to forgot password page but with email sent confirmarion
            context = {
                'email_sent': True,
                'message': f"An email has been sent to your email {email} containing instructions on how to reset your password"
            }

            # send response to frontend containing confirmation message
            return render(request, 'Authentication/forgot-password.html', context)

        except User.DoesNotExist:
            messages.error(request, 'No user found with this email.')
            return redirect('forgot-password')

    return render(request, 'Authentication/forgot-password.html')

def ResetPassword(request, email, reset_code):

    # ensure user is not logged in
    if request.user.is_authenticated:
        return redirect('home')

    try:
        # validate the password reset id
        password_reset_id = PasswordResetCode.objects.get(code=reset_code, user__email=email)

        # check for incoming post request
        if request.method == "POST":
            
            # grab the data of the submitted form
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            # make sure password reset code is till valid
            expiration_time = password_reset_id.created_at + timezone.timedelta(minutes=10)

            if timezone.now() > expiration_time:
                messages.error(request, 'Reset link has expired')

                # delete the password reset code since it has expired
                password_reset_id.delete()
                return redirect('reset-password', email=email, reset_code=reset_code)

            # check if passwords match
            if password != confirm_password:
                messages.error(request, 'Passwords do not match')
                return redirect('reset-password', email=email, reset_code=reset_code)

            # check for length of password
            if len(password) < 6:
                messages.error(request, 'Password must be at least 5 characters long')
                return redirect('reset-password', email=email, reset_code=reset_code)

            # reset the user's password
            user = password_reset_id.user
            user.set_password(password)
            user.save()

            # delete the reset code since it was just used
            password_reset_id.delete()

            messages.success(request, 'Password reset successful. Proceed to login')
            return redirect('login')
  
    except PasswordResetCode.DoesNotExist:
        messages.error(request, "Invalid reset id")
        return redirect("forgot-password")

    return render(request, 'Authentication/reset-password.html')

@login_required
def ResetPasswordFromProfile(request):

    ...