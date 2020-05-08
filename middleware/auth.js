export default function({ store, redirect, route }) {
	if (store.state.auth.user === null && route.path !== '/signup') {
		return redirect('/login')
	}
}
