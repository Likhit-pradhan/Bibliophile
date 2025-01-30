from django.contrib import admin

from book.models import Category, Book, Order, Feedback

class BookAdmin(admin.ModelAdmin):
    list_display = ('title', 'author', 'price', 'is_available')
    search_fields = ('title', )
    list_editable = ('is_available', )
    list_filter = ('is_available', 'category')

class OrderAdmin(admin.ModelAdmin):
    list_display = ('user', 'book', 'quantity', 'status')
    search_fields = ('user', 'book' )
    list_editable = ('status', )
    list_filter = ('status', )

admin.site.register(Category)
admin.site.register(Feedback)
admin.site.register(Book, BookAdmin)
admin.site.register(Order, OrderAdmin)

