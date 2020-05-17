<template>
	<div class="container">
		<div>
			<img
				src="../static/oppia.io_logo_oranssi.png"
				alt="Oppia.io"
				width="520"
				height="180"
			/>
			<h1 class="title">
				learn, succeed, repeat
			</h1>
			<form-group :items="items" />
			<div class="links">
				<a class="button" @click="login">
					Kirjaudu
				</a>
				<nuxt-link to="/signup" class="button">Rekisteröidy</nuxt-link>
			</div>
		</div>
	</div>
</template>

<script>
import FormGroup from '~/components/FormGroup.vue'
export default {
	layout: 'login',
	components: {
		FormGroup
	},
	data() {
		return {
			items: [
				{
					id: 'username',
					label: 'Käyttäjätunnus',
					input: '',
					type: 'text',
					required: true
				},
				{
					id: 'pwd',
					label: 'Salasana',
					input: '',
					type: 'password',
					required: true
				}
			]
		}
	},
	methods: {
		login() {
			let pwd = this.items.find(item => item.id === 'pwd')
			// base64 encode pwd (not secure enough for real production)
			pwd = btoa(pwd.input)
			const user = this.items.find(item => item.id === 'username')
			// check if user registered
			if (user.input === this.$store.state.profile.details.username) {
				// check if password matches the one saved in cookies
				if (pwd === this.$cookies.get('pw')) {
					this.$store.dispatch('auth/login')
					this.$router.push('/')
				} else {
					alert('Virheellinen salasana!')
				}
			} else {
				alert('Käyttäjää ei löydy!')
			}
		}
	}
}
</script>

<style>
.title {
	display: block;
	font-weight: 300;
	font-size: 46px;
	color: #ffffff;
	letter-spacing: 1px;
}

.links {
	padding-top: 15px;
}

.button {
	display: inline-block;
	border-radius: 4px;
	border: 1px solid #ffffff;
	color: #ffffff;
	text-decoration: none;
	padding: 10px 30px;
}

.button:hover {
	color: var(--color-main);
	background-color: #ffffff;
}

label {
	color: #ffffff;
}

a:not([href]) {
	color: #ffffff;
}

a:not([href]):hover {
	color: var(--color-main);
}
</style>
