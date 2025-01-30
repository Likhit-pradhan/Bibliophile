from django.shortcuts import render, HttpResponse
from django.contrib.auth.forms import UserCreationForm
from pages.forms import CustomUSerCreationForm, AddBookForm

def index(request):
    # return HttpResponse("<h1>Hello World</h1>")
    return render(request, 'pages/index.html')

def aboutus(request):
    # name = "Jhon"
    student = {1: "jhon", 2: "jane", 3 : "blake", 4: "Kriti"}
    results = {
        1 : {"name" : "Jhon", "cgpa" : [9.2, 9.8, 9.1, 9.7]},
        2 : {"name" : "Jane", "cgpa" : [8.2, 8.8, 7.1, 9.2]},
        3 : {"name" : "Sam", "cgpa" : [9.1, 9.5, 9.3, 9]},
        4 : {"name" : "Sara", "cgpa" : [9.4, 9.8, 9.2, 9.5]},
        5 : {"name" : "Will", "cgpa" : [7.2, 8.8, 9.3, 9.5]},
    }
    context = {
        "name" : "Sam",
        "age" : 20,
        "num1" : 12,
        "num2" : 10,
        "nums" : [1,2,3,4,5,10, 20, 30],
        "students" : student,
        "results" : results
    }
    return render(request, "pages/about.html", context)

def form(request):
    # form = UserCreationForm()
    form = CustomUSerCreationForm()
    context = {
        # "form": form,
        "form": AddBookForm(),
    }
    return render(request, 'pages/form.html', context)