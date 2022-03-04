
from django.urls import path , include
from . import views

urlpatterns = [
    path('', views.CartView.as_view(), name ="Cart"),
    path('add', views.addToCart.as_view(), name="add-to-cart") ,
    path('items', views.getItemsView.as_view(), name="list-item"),
    path('remove', views.removeItem.as_view(), name="remove-item") ,
    path('order', views.orderView.as_view(), name="order"),
    path('order-list', views.getOrderListView.as_view(), name="list-order"),
    path('get-items' ,views.getItemInCartView.as_view(), name="get-items")
]
