export const actions = {
	// set authentication status to true in cookies on login
	login(context) {
		window.$nuxt.$cookies.set('auth', true)
	},
	// remove authentication on logout and redirect to login page
	logout(context, vm) {
		window.$nuxt.$cookies.remove('auth')
		vm.$router.go('/login')
	}
}
