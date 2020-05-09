<template>
	<b-card :title="item.header">
		<b-card-text>{{ item.description }}</b-card-text>
		<b-form-textarea
			placeholder="Kirjoita tähän..."
			rows="8"
			max-rows="16"
		/>
		<!-- TODO: add submit button when we have an idea where this goes... -->
	</b-card>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
	name: 'Assignment',
	computed: {
		...mapGetters('content', ['contentById']),
		item() {
			return this.contentById(this.id)
		},
		id() {
			return this.$attrs.id
		}
	}
}
</script>
