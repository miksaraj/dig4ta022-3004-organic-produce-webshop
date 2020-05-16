<template>
	<div>
		<h3>{{ item.header }}</h3>
		<p>{{ item.description }}</p>
		<b-form-file
			v-model="file"
			:state="Boolean(file)"
			placeholder="Palauta vastauksesi tähän..."
			drop-placeholder="Pudota tiedosto tähän..."
			:accept="item.accept ? item.accept : ''"
		></b-form-file>
		<b-button class="btn-primary" @click="file = null">Tyhjennä</b-button>
		<b-button class="btn-primary" @click="handleSubmit">Lähetä</b-button>
	</div>
</template>

<style scoped>
.btn {
	margin-top: 1rem;
}
</style>

<script>
import { mapGetters } from 'vuex'
export default {
	name: 'ReturnAssignment',
	data() {
		return {
			file: null
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
			if (this.file) {
				this.$store.dispatch('progress/markAsDone', this.id)
			} else {
				alert('Valitse tiedosto lähetettäväksi.')
			}
		}
	}
}
</script>
