<template>
	<b-card class="bg-info">
		<h3>{{ item.header }}</h3>
		<div class="bg-light">
			<b-card-text>
				{{ item.text }}
			</b-card-text>
		</div>
	</b-card>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
	name: 'SpecialText',
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
