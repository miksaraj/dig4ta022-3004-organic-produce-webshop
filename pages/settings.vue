<template>
	<div>
		<h1>Asetukset</h1>
		<b-form-group label="Kieli">
			<b-form-radio-group v-model="lang" :options="languages" />
		</b-form-group>
		<b-button variant="warning" @click="showResetProgressMsgBox">
			Tyhjennä edistyminen
		</b-button>
		<b-button variant="danger" @click="showDeleteProfileMsgBox">
			Poista profiili
		</b-button>
	</div>
</template>

<script>
export default {
	layout: 'settings',
	data() {
		return {
			lang: 'fi',
			languages: [
				{ text: 'Suomi', value: 'fi' },
				{ text: 'Svenska', value: 'sv', disabled: true },
				{ text: 'English', value: 'en', disabled: true }
			],
			profileDeleteBox: {
				title: 'Poista profiili',
				okVariant: 'danger',
				okTitle: 'Poista',
				cancelTitle: 'Palaa takaisin',
				autoFocusButton: 'cancel',
				centered: true
			},
			profileDeleteMsg:
				'Teidät kirjataan poiston jälkeen välittömästi ulos. Oletko varma, että haluat poistaa profiilisi?',
			resetProgressBox: {
				title: 'Aloita alusta',
				okTitle: 'Kyllä',
				cancelTitle: 'Ei',
				autoFocusButton: 'cancel',
				centered: true
			},
			resetProgressMsg:
				'Oletko varma, että haluat aloittaa kurssin alusta?'
		}
	},
	methods: {
		showDeleteProfileMsgBox() {
			const profileDeleteBox = this.profileDeleteBox
			this.$bvModal
				.msgBoxConfirm(this.profileDeleteMsg, profileDeleteBox)
				.then(value => {
					if (value === true) {
						this.deleteProfile()
					}
				})
				.catch(error => {
					alert(error)
				})
		},
		showResetProgressMsgBox() {
			const resetProgressBox = this.resetProgressBox
			this.$bvModal
				.msgBoxConfirm(this.resetProgressMsg, resetProgressBox)
				.then(value => {
					if (value === true) {
						this.resetProgress()
					}
				})
				.catch(error => {
					alert(error)
				})
		},
		deleteProfile() {
			const { dispatch } = this.$store
			dispatch('profile/clear')
			dispatch('progress/clear')
			dispatch('auth/logout', this)
		},
		resetProgress() {
			this.$store.dispatch('progress/clear')
		}
	}
}
</script>
