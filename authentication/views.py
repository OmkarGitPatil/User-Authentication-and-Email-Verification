from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.utils.encoding import force_str
from django.core.mail import EmailMessage
from .tokens import generate_token
from authl import settings
# Create your views here.


def index(request):
    return render(request, 'authentication/index.html')


def signup(request):

    if request.method == 'POST':

        username = request.POST['username']

        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

        if User.objects.filter(username=username).first():
            messages.error(
                request, "This username is already exist! Please try some other username.")
            return render(request, 'authentication/signup.html', {'error': True, 'message': 'Username Already Exist'})

        if User.objects.filter(email=email):
            messages.error(
                request, "This email is already registered! ")
            return render(request, 'authentication/signup.html', {'error': True, 'message': 'Email Already Registered'})

        if len(username) > 10:
            messages.error(request, 'Username must not exceed 10 characters.')
            return render(request, 'authentication/signup.html', {'error': True, 'message': 'Email Already Registered'})

        if pass1 != pass2:
            messages.error(request, 'Password did not match')
            return render(request, 'authentication/signup.html', {'error': True, 'message': 'Password did not match'})

        if not username.isalnum():
            messages.error(
                request, 'Username must have only characters and numbers')
            return render(request, 'authentication/signup.html', {'error': True, 'message': 'Username must have only characters and numbers'})

        myuser = User.objects.create_user(username, email, pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False
        myuser.save()

        messages.success(request, 'Your Account has been created successfully')

        # Welcome Email

        subject = 'Welcome to authl Django Login!'
        message = 'Hello ' + myuser.first_name + '!!\n' + \
            'Welcome to authl \n Thank you for visiting our website. In order to activate your account please confirm your email.'

        from_email = settings.EMAIL_HOST_USER
        to_user = [myuser.email]
        send_mail(subject, message, from_email, to_user, fail_silently=True)

        # Email Address Confirmation Email

        current_site = get_current_site(request)
        email_subject = 'Confirm your email @ auth- Django Login'
        message2 = render_to_string('email_confirmation.html', {
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser),
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
        )
        email.fail_silently = True
        email.send()

        return redirect('signin')

    return render(request, 'authentication/signup.html')


def signin(request):

    if request.method == 'POST':
        username = request.POST['username']
        pass1 = request.POST['pass1']

        user = authenticate(username=username, password=pass1)

        if user is not None:
            login(request, user)
            fname = user.first_name
            return render(request, 'authentication/index.html', {'fname': fname, 'user': user})

        else:
            messages.error(
                request, 'We have no such user. Please check username and password or click on Sign Up')
            return redirect('index')

    return render(request, 'authentication/signin.html')


def signout(request):
    logout(request)
    messages.success(request, 'Logged Out Successfully')
    return redirect('index')


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    print(uid)
    print(myuser)
    print(myuser.first_name)

    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        login(request, myuser)
        return redirect('index')
    else:
        return render(request, 'activation_failed.html')
