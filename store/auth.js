export const actions = {
	login(context) {
		window.$nuxt.$cookies.set('auth', true)
	},
	logout(context, vm) {
		window.$nuxt.$cookies.remove('auth')
		vm.$router.go('/login')
	}
}
