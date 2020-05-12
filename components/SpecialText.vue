<template>
	<b-card class="bg-info">
		<h3>{{ item.header }}</h3>
		<div v-for="section in item.text" :key="section.type" class="bg-light">
			<b-card-text>
				<i v-if="section.type == 'p'">{{ section.content }}</i>
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
