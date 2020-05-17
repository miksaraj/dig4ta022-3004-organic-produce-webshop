<template>
	<b-card class="special-text">
		<h3>{{ item.header }}</h3>
		<div class="special-text">
			<b-card-text>
				{{ item.text }}
			</b-card-text>
		</div>
	</b-card>
</template>

<style scoped>
.special-text {
	background-color: var(--color-secondary);
	color: whitesmoke;
}

.card.special-text {
	margin-bottom: 2rem;
}
</style>

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
