<template>
	<b-card :title="item.header" text-variant="white" class="bg-primary">
		<b-form-group class="mb-0" :label="item.description">
			<!--	//	v-model="text" -->
			<!--	:state="text.length >= 50" -->
			<b-form-textarea
				placeholder="Kirjoita tähän vähintään 50 sanaa..."
				rows="8"
				max-rows="16"
			/>
		</b-form-group>
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
		},
		data() {
			return {
				text: ''
			}
		}
	}
}
</script>
