<template>
	<div>
		<h3>{{ item.header }}</h3>
		<div v-for="section in item.text" :key="section.type">
			<p v-if="section.type == 'p'">{{ section.content }}</p>
			<ul v-else-if="section.type == 'ul'">
				<li v-for="listItem in section.content" :key="listItem">
					{{ listItem }}
				</li>
			</ul>
		</div>
	</div>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
	name: 'TheoryElement',
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
