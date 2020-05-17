<template>
	<div>
		<h1>Oma profiili</h1>
		<b-row>
			<b-col>
				<form-group
					id="profile-form"
					:items="items"
					:readOnly="readOnly"
				/>
				<div v-if="!readOnly">
					<b-button class="btn cancel" @click="toggleEditMode">
						Peruuta
					</b-button>
					<b-button class="btn save" @click="saveProfile">
						Tallenna
					</b-button>
				</div>
				<b-button
					v-else
					class="btn btn-primary"
					@click="toggleEditMode"
				>
					Muokkaa profiilia
				</b-button>
				<!-- TODO: Add change password functionality -->
			</b-col>
			<b-col>
				<p>Edistystietoa...</p>
			</b-col>
		</b-row>
	</div>
</template>

<style>
.btn.save {
	background-color: var(--color-3);
	float: right;
}

.btn.save:hover,
.btn.save:active,
.btn.save:focus {
	background-color: var(--color-4);
}

label {
	color: unset !important;
}
</style>

<script>
import FormGroup from '~/components/FormGroup.vue'
export default {
	layout: 'settings',
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
					id: 'email',
					label: 'Sähköpostiosoite',
					input: '',
					type: 'email',
					required: true
				},
				{
					id: 'name',
					label: 'Etu- ja sukunimi',
					input: '',
					type: 'text'
				}
			],
			readOnly: true
		}
	},
	computed: {
		profile() {
			return this.$store.state.profile.details
		}
	},
	created() {
		this.assignProfileDetails()
	},
	methods: {
		assignProfileDetails() {
			const items = this.items
			for (const [key, value] of Object.entries(this.profile)) {
				const idx = items.findIndex(x => x.id === key)
				this.$set(items[idx], 'input', value)
			}
			this.items = items
		},
		toggleEditMode() {
			this.readOnly = !this.readOnly
		},
		saveProfile() {
			const profile = {}
			for (let i = 0; i < this.items.length; i++) {
				const element = this.items[i]
				const key = element.id
				profile[key] = element.input
			}
			this.$store.dispatch('profile/update', profile)
			this.toggleEditMode()
		}
	}
}
</script>
