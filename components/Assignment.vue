<template>
	<b-card :title="item.header" text-variant="white" class="assignment-card">
		<b-form-group class="mb-0" :label="item.description">
			<b-form-textarea
				:placeholder="item.placeholder"
				v-model="text"
				rows="8"
				max-rows="16"
			/>
		</b-form-group>
		<b-button class="btn-primary" @click="handleSubmit">Lähetä</b-button>
	</b-card>
</template>

<style scoped>
.assignment-card {
	background-color: var(--color-3);
}

.card.assignment-card {
	margin-bottom: 2rem;
}

.btn-primary {
	margin-top: 0.5rem;
}
</style>

<script>
import { mapGetters } from 'vuex'
export default {
	name: 'Assignment',
	data() {
		return {
			text: ''
		}
	},
	computed: {
		...mapGetters('content', ['contentById']),
		item() {
			return this.contentById(this.id)
		},
		id() {
			return this.$attrs.id
		}
	},
	methods: {
		handleSubmit() {
			if (this.text.length >= 50) {
				this.$store.dispatch('progress/markAsDone', this.id)
			} else {
				alert('Kirjoita nyt muutama sana vielä...')
			}
		}
	}
}
</script>
