export default function({ redirect, route, app }) {
	if (!app.$cookies.get('auth') && route.path !== '/signup') {
		return redirect('/login')
	}
}
