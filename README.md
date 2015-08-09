# My Exercise

#Exercise Using Jquery,with server code (Sinatra,node etc) and some persistence
layer, create an appealing application that:
1. Allows a user to register for the app
2. View specialized content when logged in (* any content is fine – Lorem Ipsum)
3. Sign In as Registered user
4. Sign Out registered user and returns to unauthenticated state
Register:
 The Registration function asks the user for: email address, password, and username
 Registration ensures email is not a duplicate and username is unique
 Send email confirmation
 Activate account once user has ‘accepted’ via email link
Sign In
 Accept user email and password
 Display user’s user name once authenticated
 Display some content not visible when users are not authenticated
 By default Persist login in for 72hr
 Asks if user wants to “remember login”
Sign Out
 Returns user to unauthenticated state


## Technology

Server side, built with the [Express](http://expressjs.com/)
using [MongoDB](http://www.mongodb.org/) as a data store.


| On The Server | On The Client  | 
| ------------- | -------------- | 
| Express       | Bootstrap      | 
| Jade          | jQuery         |
| Mongoose      |                |
| Passport      | 	         |
| Async         | 		 |
|nodemailer	|


## License

MIT
